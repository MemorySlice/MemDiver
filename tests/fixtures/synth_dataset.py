"""Synthetic realistic-dataset orchestrator.

The ``requires_dataset`` tests were originally gated behind the private
``mempdumps`` tree (real gcore cores, gdb/lldb raw region dumps, boringssl
TLS 1.3 ``.dump`` trees). To make the suite run in full on any machine and in
CI, this module materialises *synthetic equivalents* of those captures under
``tests/fixtures/``, reusing the same on-disk layout the tests expect.

Resolution is hybrid (see :func:`tests._paths.dataset_file`): a real capture is
used where present, and these synthetic artifacts fill the gaps. Every builder
is idempotent — it returns immediately if its output already exists — so this
is safe to call from both ``pytest_configure`` and lazily per resource.

The concrete builders live in sibling modules so the three artifact families
(ELF cores, raw region dumps, boringssl trees) stay independently testable:

* :mod:`tests.fixtures.synth_elf_core`     -> ``gcore.core`` + ``meta.json``
* :mod:`tests.fixtures.synth_raw_regions`  -> ``gdb_raw`` / ``lldb_raw`` pairs
* :mod:`tests.fixtures.synth_boringssl`    -> TLS 1.3 boringssl ``.dump`` trees
"""
from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent

# Root for ``dataset_root()``-style resources (mirrors the private dataset
# layout: ``<root>/dataset_memory_slice/...`` and ``<root>/TLS13/...``).
#
# Deliberately SEPARATE from ``generate_fixtures.DATASET_ROOT``
# (``tests/fixtures/dataset``): that dir holds the small ``scenario_a`` TLS/SSH
# fixtures which ``tests/test_integration.py`` scans and asserts an exact run
# count on. Emitting the realistic captures (incl. the 100-run boringssl tree)
# into a distinct root keeps that scan — and any future whole-root scan of the
# scenario dataset — unpolluted.
SYNTH_DATASET_ROOT = _HERE / "synthetic_dataset"

# Root for ``MEMDIVER_FIXTURE_ROOT``-style resources. This matches the default
# used by tests/test_proc_maps_parser.py and tests/test_regioned_raw_source.py
# (``tests/fixtures/datasets``), so populating it makes their import-time
# ``skipif(not <file>.exists())`` guards pass with no test edits.
FIXTURE_DATASETS_ROOT = _HERE / "datasets"

# The single gocryptfs run directory the core/metadata tests look under.
GCORE_RUN_DIR = (
    SYNTH_DATASET_ROOT
    / "dataset_memory_slice"
    / "gocryptfs"
    / "dataset_gocryptfs"
    / "run_0001"
)

# Process-level short-circuit so repeated calls (per resource + pytest_configure)
# don't re-stat every sentinel. The builders are individually idempotent too.
_ensured = False


def ensure_synthetic_dataset() -> None:
    """Materialise every synthetic dataset artifact (idempotent)."""
    global _ensured
    if _ensured:
        return
    from tests.fixtures import (
        synth_boringssl,
        synth_elf_core,
        synth_raw_regions,
    )

    synth_raw_regions.build(FIXTURE_DATASETS_ROOT / "gocryptfs" / "run_0001")
    synth_elf_core.build(GCORE_RUN_DIR)
    synth_boringssl.build(SYNTH_DATASET_ROOT)
    _ensured = True


if __name__ == "__main__":
    ensure_synthetic_dataset()
    print(f"Synthetic dataset ensured under: {SYNTH_DATASET_ROOT}")
    print(f"Fixture-root resources under:    {FIXTURE_DATASETS_ROOT}")
