"""Alignment provenance on ``ConsensusVector`` (plan item A1).

Every consensus now says HOW its N dumps were put into correspondence, and
warns exactly when that correspondence is questionable. The three methods and
the one silence are pinned here:

* ``file_offset`` — the flat fallback. Silent on equal-sized dumps (the normal
  case for a phase series of one process), loud when the sizes differ.
* ``virtual_address`` — gcore / regioned-raw captures aligned on their VA map.
* ``module_offset`` — native ``.msl``, unchanged behaviour.
"""

import struct
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    PF_R,
    PT_LOAD,
    _EHDR64_SIZE,
    _PHDR64_FMT,
    _PHDR64_SIZE,
)
from memdiver.core.dump_source import MslDumpSource, RawDumpSource
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.core.region_align import VA_PAGE_SIZE
from memdiver.core.variance import ByteClass
from memdiver.engine.consensus import (
    ALIGNMENT_FILE_OFFSET,
    ALIGNMENT_METHODS,
    ALIGNMENT_MODULE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
    AlignmentReport,
    ConsensusVector,
)
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE, _build_file_header, _build_memory_region
from tests.fixtures.tls_ground_truth import tls_dumps_dir


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _raw_sources(tmp_path, *blobs):
    """Open one RawDumpSource per blob; the caller closes them."""
    sources = []
    for i, blob in enumerate(blobs):
        p = tmp_path / f"raw{i}.dump"
        p.write_bytes(blob)
        src = RawDumpSource(p)
        src.open()
        sources.append(src)
    return sources


def _write_core(tmp_path: Path, name: str, segments) -> Path:
    """Write a minimal ELF64 ET_CORE with one PT_LOAD per ``(vaddr, body)``."""
    e_phnum = len(segments)
    e_phoff = _EHDR64_SIZE
    data_off = e_phoff + e_phnum * _PHDR64_SIZE

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, e_phoff, 0, 0,
        _EHDR64_SIZE, _PHDR64_SIZE, e_phnum, 0, 0, 0,
    )

    phdrs = b""
    bodies = b""
    offset = data_off
    for vaddr, body in segments:
        phdrs += struct.pack(
            _PHDR64_FMT, PT_LOAD, PF_R, offset, vaddr, vaddr,
            len(body), len(body), VA_PAGE_SIZE,
        )
        bodies += body
        offset += len(body)

    p = tmp_path / name
    p.write_bytes(ehdr + phdrs + bodies)
    return p


def _gcore_sources(tmp_path, *segment_sets):
    """Open one GCoreDumpSource per segment set; the caller closes them."""
    sources = []
    for i, segments in enumerate(segment_sets):
        src = GCoreDumpSource(_write_core(tmp_path, f"core{i}.core", segments))
        src.open()
        sources.append(src)
    return sources


def _native_msl(path: Path, base_addr: int, page_data: bytes) -> Path:
    """A minimal native (non-imported) MSL file with one memory region."""
    import random
    rng = random.Random(42)
    dump_uuid = bytes(rng.getrandbits(8) for _ in range(16))
    region_block, _ = _build_memory_region(
        base_addr=base_addr, num_pages=1, page_data=page_data,
    )
    path.write_bytes(_build_file_header(dump_uuid, 1_700_000_000_000_000_000)
                     + region_block)
    return path


def _build(sources) -> ConsensusVector:
    cm = ConsensusVector()
    try:
        cm.build_from_sources(sources)
    finally:
        for s in sources:
            s.close()
    return cm


# ---------------------------------------------------------------------------
# The report shape
# ---------------------------------------------------------------------------


def test_an_unbuilt_vector_reports_nothing_rather_than_lying():
    report = ConsensusVector().alignment_report
    assert report.method == ALIGNMENT_FILE_OFFSET
    assert report.n_sources == 0
    assert report.bytes_compared == 0
    assert report.warnings == ()


def test_to_dict_is_json_ready_and_uses_the_closed_vocabulary():
    report = AlignmentReport(
        method=ALIGNMENT_VIRTUAL_ADDRESS, bytes_compared=10,
        bytes_discarded=4, sizes_differed=True, n_sources=2,
        warnings=("careful",),
    )
    assert report.to_dict() == {
        "method": "virtual_address",
        "bytes_compared": 10,
        "bytes_discarded": 4,
        "sizes_differed": True,
        "n_sources": 2,
        "warnings": ["careful"],
    }
    assert report.method in ALIGNMENT_METHODS


def test_the_vocabulary_is_exactly_three_methods():
    assert ALIGNMENT_METHODS == (
        ALIGNMENT_MODULE_OFFSET, ALIGNMENT_VIRTUAL_ADDRESS, ALIGNMENT_FILE_OFFSET,
    )


def test_the_report_is_frozen():
    """Provenance a caller can edit after the fact is not provenance."""
    with pytest.raises(FrozenInstanceError):
        ConsensusVector().alignment_report.method = "nonsense"


# ---------------------------------------------------------------------------
# The flat path: silent when it is fine, loud when it is not
# ---------------------------------------------------------------------------


def test_equal_sized_raw_dumps_report_file_offset_and_stay_silent(tmp_path):
    """The normal case. A warning here would be noise on every real run."""
    blob = bytes(range(256))
    cm = _build(_raw_sources(tmp_path, blob, blob, blob))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_FILE_OFFSET
    assert report.sizes_differed is False
    assert report.bytes_compared == 256
    assert report.bytes_discarded == 0
    assert report.n_sources == 3
    assert report.warnings == ()


def test_differently_sized_raw_dumps_warn_and_name_the_discarded_bytes(tmp_path):
    cm = _build(_raw_sources(tmp_path, b"\x00" * 100, b"\x00" * 130, b"\x00" * 180))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_FILE_OFFSET
    assert report.sizes_differed is True
    assert report.bytes_compared == 100  # min(sizes)
    assert report.bytes_discarded == (100 + 130 + 180) - 3 * 100
    assert len(report.warnings) == 1
    warning = report.warnings[0]
    assert "110 bytes were discarded" in warning
    assert "without ASLR correction" in warning
    assert "file-offset" in warning


def test_flat_coverage_reconciles_against_the_inputs(tmp_path):
    sizes = (64, 96, 128)
    cm = _build(_raw_sources(tmp_path, *(b"\xAA" * n for n in sizes)))
    report = cm.alignment_report
    assert (report.bytes_compared * report.n_sources
            + report.bytes_discarded) == sum(sizes)


def test_the_path_taking_build_reports_the_same_coverage(tmp_path):
    """``build(paths)`` is the same flat truncation and says so."""
    paths = []
    for i, n in enumerate((40, 55)):
        p = tmp_path / f"d{i}.dump"
        p.write_bytes(b"\x11" * n)
        paths.append(p)
    cm = ConsensusVector()
    cm.build(paths)
    assert cm.alignment_report.method == ALIGNMENT_FILE_OFFSET
    assert cm.alignment_report.bytes_compared == 40
    assert cm.alignment_report.bytes_discarded == 15
    assert cm.alignment_report.sizes_differed is True
    assert cm.alignment_report.warnings


def test_the_incremental_fold_reports_what_it_truncated():
    cm = ConsensusVector()
    cm.build_incremental(50)
    cm.add_source(b"\x00" * 50)
    cm.add_source(b"\x01" * 70)
    cm.finalize()
    report = cm.alignment_report
    assert report.method == ALIGNMENT_FILE_OFFSET
    assert report.bytes_compared == 50
    assert report.bytes_discarded == 20
    assert report.sizes_differed is True
    assert report.warnings


def test_the_incremental_fold_is_silent_on_equal_inputs():
    cm = ConsensusVector()
    cm.build_incremental(50)
    cm.add_source(b"\x00" * 50)
    cm.add_source(b"\x01" * 50)
    cm.finalize()
    assert cm.alignment_report.warnings == ()
    assert cm.alignment_report.sizes_differed is False


# ---------------------------------------------------------------------------
# The virtual-address path
# ---------------------------------------------------------------------------


def test_a_gcore_pair_takes_the_va_path(tmp_path):
    """Two cores mapping the same VA range align on it, not on file offsets."""
    body_a = b"A" * 32
    body_b = b"A" * 16 + b"B" * 16
    cm = _build(_gcore_sources(
        tmp_path, [(0x400000, body_a)], [(0x400000, body_b)],
    ))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert report.bytes_compared == 32
    assert report.bytes_discarded == 0
    assert report.sizes_differed is False
    assert report.warnings == ()
    # The variance is non-zero exactly where the two dumps differ.
    assert cm.size == 32
    assert list(np.nonzero(np.asarray(cm.variance))[0]) == list(range(16, 32))


def test_the_va_path_survives_a_shifted_file_layout(tmp_path):
    """The point of aligning on VA: same VA, different file offset.

    The second core carries an extra leading segment, so every byte of the
    shared region sits at a different *file* offset — flat alignment would
    compare the wrong bytes. VA alignment compares the right ones and reports
    the leading segment as discarded.
    """
    shared = bytes(range(64))
    cm = _build(_gcore_sources(
        tmp_path,
        [(0x800000, shared)],
        [(0x100000, b"\xFF" * 48), (0x800000, shared)],
    ))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert report.bytes_compared == 64
    assert report.bytes_discarded == 48
    assert report.sizes_differed is True
    assert cm.reference_bytes == shared
    # Identical bytes at the shared VA -> invariant everywhere.
    assert all(c == ByteClass.INVARIANT for c in cm.classifications)


def test_the_va_path_warns_when_it_drops_a_significant_share(tmp_path):
    """48 of 112 offered bytes is well past the 10 % discard threshold."""
    shared = b"\x00" * 64
    cm = _build(_gcore_sources(
        tmp_path,
        [(0x800000, shared)],
        [(0x100000, b"\xFF" * 48), (0x800000, shared)],
    ))
    (warning,) = cm.alignment_report.warnings
    assert "virtual_address" in warning
    assert "48 bytes" in warning
    assert "not all" in warning


def test_va_pages_are_cut_on_absolute_page_boundaries(tmp_path):
    """A region longer than a page aligns page by page, tail included."""
    body = bytes(VA_PAGE_SIZE) + b"\x01" * 100
    cm = _build(_gcore_sources(
        tmp_path, [(0x400000, body)], [(0x400000, body)],
    ))
    assert cm.alignment_report.bytes_compared == len(body)
    assert cm.size == len(body)
    # Two slices: one full page plus the 100-byte tail.
    assert [(off, size) for off, size, _ in cm.msl_layout] == [
        (0, VA_PAGE_SIZE), (VA_PAGE_SIZE, 100),
    ]


def test_the_va_layout_maps_slab_offsets_back_to_addresses(tmp_path):
    """``msl_layout`` carries the VA of each slice, so overlays still work."""
    cm = _build(_gcore_sources(
        tmp_path,
        [(0x400000, b"a" * 8), (0x500000, b"b" * 8)],
        [(0x400000, b"a" * 8), (0x500000, b"c" * 8)],
    ))
    assert cm.msl_layout == [
        (0, 8, [0x400000, 0x400000]),
        (8, 8, [0x500000, 0x500000]),
    ]
    # Ascending VA order, so slab offsets read like addresses.
    assert cm.dump_index_for_path(cm.dump_paths[1]) == 1


def test_gcore_dumps_sharing_no_address_compare_nothing_and_say_so(tmp_path):
    cm = _build(_gcore_sources(
        tmp_path, [(0x400000, b"x" * 16)], [(0x900000, b"x" * 16)],
    ))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert report.bytes_compared == 0
    assert cm.size == 0
    assert "no bytes common to all 2 dumps" in report.warnings[0]


def test_a_source_with_no_va_map_still_takes_the_flat_path(tmp_path):
    """Additive: RawDumpSource has no VA map and behaves exactly as before."""
    blob = b"\x42" * 64
    cm = _build(_raw_sources(tmp_path, blob, blob))
    assert cm.alignment_report.method == ALIGNMENT_FILE_OFFSET
    assert cm.size == 64
    assert cm.msl_layout is None


def test_a_mixed_set_falls_back_to_the_flat_path(tmp_path):
    """One VA-mapped source is not enough; correspondence must hold for all."""
    raw = _raw_sources(tmp_path, b"\x42" * 64)[0]
    core = _gcore_sources(tmp_path, [(0x400000, b"\x42" * 64)])[0]
    cm = ConsensusVector()
    try:
        # The flat path reads whole sources; gcore deliberately has no
        # read_all (its views can be multi-GB), so a mixed set cannot be
        # flattened. Pre-existing behaviour, unchanged by this item.
        with pytest.raises(AttributeError):
            cm.build_from_sources([raw, core])
    finally:
        raw.close()
        core.close()
    assert cm.alignment_report.method == ALIGNMENT_FILE_OFFSET


# ---------------------------------------------------------------------------
# The module-offset path (unchanged behaviour, now reported)
# ---------------------------------------------------------------------------


def test_native_msl_reports_module_offset(tmp_path):
    page_data = b"\xDE\xAD" * (PAGE_SIZE // 2)
    sources = []
    for i, base in enumerate((0x7FFF00000000, 0x7FFF10000000)):
        src = MslDumpSource(_native_msl(tmp_path / f"d{i}.msl", base, page_data))
        src.open()
        sources.append(src)
    cm = _build(sources)

    report = cm.alignment_report
    assert report.method == ALIGNMENT_MODULE_OFFSET
    assert report.n_sources == 2
    # Existing behaviour pinned: one page, aligned despite the ASLR shift.
    assert cm.size == PAGE_SIZE
    assert report.bytes_compared == PAGE_SIZE
    assert report.bytes_discarded == 0
    assert report.sizes_differed is False
    assert report.warnings == ()
    assert cm.classification_counts()["invariant"] == PAGE_SIZE
    assert cm.msl_layout is not None


# ---------------------------------------------------------------------------
# Real data — the corpus this item must NOT change
# ---------------------------------------------------------------------------


@pytest.mark.requires_dataset
def test_real_openssl_run_keeps_its_measured_histogram():
    """The eight ``openssl_run_12_1`` dumps, byte for byte as measured.

    They are equal-sized raw memory with no VA map anywhere in the run
    directory, so the flat path is both what runs and what is correct: the
    99.945 % invariance is only reachable if the alignment is right. The
    report must therefore say ``file_offset``, discard nothing, and warn about
    nothing — and the class histogram must not move by a single byte.
    """
    run = (tls_dumps_dir() / "TLS12" / "100_iterations_Abort" / "openssl"
           / "openssl_run_12_1")
    paths = sorted(run.glob("*.dump"))
    if len(paths) != 8:
        pytest.skip(f"corpus run not available at {run}")

    from memdiver.engine.consensus_service import build_consensus
    cm = build_consensus(paths)

    assert cm.alignment_report.to_dict() == {
        "method": ALIGNMENT_FILE_OFFSET,
        "bytes_compared": 11_223_040,
        "bytes_discarded": 0,
        "sizes_differed": False,
        "n_sources": 8,
        "warnings": [],
    }
    assert cm.classification_counts() == {
        "invariant": 11_216_911,
        "structural": 1_652,
        "pointer": 2_566,
        "key_candidate": 1_911,
    }


# ---------------------------------------------------------------------------
# The same VA path, from a regioned raw dump's .maps sidecar
# ---------------------------------------------------------------------------


def _gdb_raw_source(tmp_path: Path, name: str, regions):
    """A ``gdb_raw.bin`` + ``.maps`` pair from ``(start_va, body)`` regions."""
    from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource

    bin_path = tmp_path / f"{name}.gdb_raw.bin"
    bin_path.write_bytes(b"".join(body for _, body in regions))
    (tmp_path / f"{name}.gdb_raw.maps").write_text("".join(
        f"{start:x}-{start + len(body):x} rw-p 00000000 00:00 0 \n"
        for start, body in regions
    ), encoding="utf-8")
    src = GdbRawDumpSource(bin_path)
    src.open()
    return src


def test_regioned_raw_dumps_share_the_va_path(tmp_path):
    """gdb_raw exposes the same ``iter_ranges`` contract, so it aligns the same.

    The two bins hold the shared region at different *bin* offsets — the
    second carries an extra leading region — so only VA alignment lines the
    shared bytes up.
    """
    shared = bytes(range(64))
    sources = [
        _gdb_raw_source(tmp_path, "a", [(0x7F0000000000, shared)]),
        _gdb_raw_source(tmp_path, "b", [(0x100000, b"\xEE" * 32),
                                        (0x7F0000000000, shared)]),
    ]
    cm = _build(sources)
    report = cm.alignment_report
    assert report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert report.bytes_compared == 64
    assert report.bytes_discarded == 32
    assert cm.reference_bytes == shared
    assert cm.msl_layout == [(0, 64, [0x7F0000000000, 0x7F0000000000])]
