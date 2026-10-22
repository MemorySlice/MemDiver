"""Single-dump analysis on gcore ELF cores and gdb_raw / lldb_raw dumps.

Covers the ``read_all`` those sources gained, the flat-view helpers in
``app/pipeline/analysis_buffer.py`` (every read names the ``read_all`` view,
because these sources default ``read_range`` to ``"raw"`` and ``size`` to the
raw file size), the strategy choice (bytes / mmap of the ``.bin`` prefix /
spill of a gcore), the one-copy ``read_all`` heap peak, and ``run_file`` end to
end with hits at the planted ``vas`` offsets.
"""

from __future__ import annotations

import json
import logging
import mmap
import os
import struct
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
import pytest

from memdiver.app.pipeline.analysis_buffer import (
    STRATEGY_BYTES,
    STRATEGY_MMAP,
    STRATEGY_SPILL,
    estimate_read_all,
    flat_view,
    flat_view_size,
    open_analysis_buffer,
    plan_analysis_buffer,
    read_estimate_sample,
    read_flat_range,
    spill_flat_view,
)
from memdiver.app.pipeline.analysis_task_runner import run_file
from memdiver.core.binary_formats.elf_core_reader import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    ET_CORE,
    PF_R,
    PF_W,
    PT_LOAD,
    _EHDR64_SIZE,
    _PHDR64_FMT,
    _PHDR64_SIZE,
)
from memdiver.core.dump_source import open_dump
from tests.fixtures import synth_elf_core, synth_raw_regions

BUFFER_LOGGER = "memdiver.app.pipeline.analysis_buffer"
SECRET = b"secret=ABCDEF01"
SECRET_REGEX = r"secret=[A-F0-9]{8}"


@dataclass
class _FakeCtx:
    task_id: str = "test-analysis-buffer-regioned"
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

#: (vaddr, filesz, memsz) per PT_LOAD, in program-header order.
Segment = Tuple[int, bytes, int]


def _write_core(path: Path, segments: Sequence[Segment],
                reverse_bodies: bool = True) -> Path:
    """ELF64 ET_CORE whose PT_LOAD bodies are stored in REVERSE file order.

    Reversing proves the ``vas`` view follows the program-header table, not
    the file layout; a ``memsz > filesz`` / ``filesz == 0`` segment proves
    only captured bytes count.
    """
    e_phnum = len(segments)
    data_off = _EHDR64_SIZE + e_phnum * _PHDR64_SIZE
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ELF_MAGIC + bytes([ELFCLASS64, ELFDATA2LSB, 1]) + b"\x00" * 9,
        ET_CORE, 62, 1, 0, _EHDR64_SIZE, 0, 0, _EHDR64_SIZE, _PHDR64_SIZE,
        e_phnum, 0, 0, 0,
    )
    order = list(range(e_phnum))[::-1] if reverse_bodies else list(range(e_phnum))
    offsets: Dict[int, int] = {}
    cursor = data_off
    for idx in order:
        offsets[idx] = cursor
        cursor += len(segments[idx][1])
    phdrs = b"".join(
        struct.pack(_PHDR64_FMT, PT_LOAD, PF_R | PF_W, offsets[i], vaddr, vaddr,
                    len(body), memsz, 0x1000)
        for i, (vaddr, body, memsz) in enumerate(segments))
    path.write_bytes(ehdr + phdrs + b"".join(segments[i][1] for i in order))
    return path


def _random(n: int, seed: int) -> bytes:
    return np.random.default_rng(seed).integers(0, 256, n, dtype=np.uint8).tobytes()


def _body(size: int, plant_at: int = -1, payload: bytes = b"") -> bytes:
    body = bytearray(b"\x00" * size)
    if plant_at >= 0:
        body[plant_at:plant_at + len(payload)] = payload
    return bytes(body)


def _gcore_segments() -> List[Segment]:
    """Four PT_LOADs: a zero-filesz one and a filesz < memsz one included."""
    return [
        (0x400000, _body(0x1000, 0x100, SECRET), 0x1000),
        (0x500000, b"", 0x2000),                                    # no content
        (0x600000, _body(0x3000, 0x2000, _random(256, 1)), 0x4000),  # memsz > filesz
        (0x700000, _body(0x1000, 0x800, SECRET), 0x1000),
    ]


#: vas offsets of the planted payloads in :func:`_gcore_segments`.
GCORE_SECRET_VAS = [0x100, 0x1000 + 0x3000 + 0x800]
GCORE_KEY_VAS = 0x1000 + 0x2000


@pytest.fixture
def gcore_dump(tmp_path: Path) -> Path:
    return _write_core(tmp_path / "planted.core", _gcore_segments())


def _write_regioned(run_dir: Path, flavour: str, padding: int = 0) -> Path:
    """``<flavour>.bin`` + ``.maps``: 3 non-adjacent regions, planted payloads."""
    regions = [
        (0x10000, _body(0x1000, 0x40, SECRET)),
        (0x30000, _body(0x2000, 0x1000, _random(256, 2))),
        (0x50000, _body(0x1000, 0x900, SECRET)),
    ]
    run_dir.mkdir(parents=True, exist_ok=True)
    maps = "".join(f"{start:08x}-{start + len(body):08x} rw-p 00000000 00:00 0\n"
                   for start, body in regions)
    (run_dir / f"{flavour}.maps").write_text(maps)
    bin_path = run_dir / f"{flavour}.bin"
    bin_path.write_bytes(b"".join(body for _, body in regions)
                         + b"\xEE" * padding)
    return bin_path


#: vas (== bin) offsets of the planted payloads in :func:`_write_regioned`.
REGIONED_SECRET_VAS = [0x40, 0x1000 + 0x2000 + 0x900]
REGIONED_KEY_VAS = 0x1000 + 0x1000


@pytest.fixture
def gdb_dump(tmp_path: Path) -> Path:
    return _write_regioned(tmp_path / "gdb", "gdb_raw")


@pytest.fixture
def lldb_dump(tmp_path: Path) -> Path:
    return _write_regioned(tmp_path / "lldb", "lldb_raw")


@pytest.fixture(params=["gdb_dump", "lldb_dump"])
def regioned_dump(request) -> Path:
    return request.getfixturevalue(request.param)


@pytest.fixture
def padded_lldb(tmp_path: Path) -> Path:
    return _write_regioned(tmp_path / "padded", "lldb_raw", padding=0x777)


def _iter_ranges_bytes(source, file_bytes: bytes) -> bytes:
    return b"".join(file_bytes[off:off + (end - start)]
                    for start, end, off in source.iter_ranges("vas"))


# ---------------------------------------------------------------------------
# read_all on the sources
# ---------------------------------------------------------------------------


def test_gcore_read_all_is_the_ptload_concatenation(gcore_dump):
    raw = gcore_dump.read_bytes()
    with open_dump(gcore_dump) as source:
        assert source.format_name == "gcore"
        flat = source.read_all()
        assert flat == _iter_ranges_bytes(source, raw)
        assert flat == source.read_range(0, source.size_for("vas"), view="vas")
        assert len(flat) == source.size_for("vas") == 0x1000 + 0x3000 + 0x1000
        assert source.read_all("raw") == raw
        assert flat != raw[:len(flat)]  # headers + reversed bodies: not a prefix
        with pytest.raises(ValueError):
            source.read_all("va")


def test_gcore_read_all_on_the_shared_fixture(tmp_path):
    synth_elf_core.build(tmp_path)
    core = tmp_path / "gcore.core"
    with open_dump(core) as source:
        assert source.read_all() == _iter_ranges_bytes(source, core.read_bytes())


def test_gcore_read_all_leaves_the_mapping_closable(gcore_dump):
    source = open_dump(gcore_dump)
    source.open()
    source.read_all()
    source.close()  # a leaked memoryview export would raise BufferError here


def test_regioned_read_all_is_the_bin_prefix(regioned_dump):
    raw = regioned_dump.read_bytes()
    with open_dump(regioned_dump) as source:
        flat = source.read_all()
        assert flat == _iter_ranges_bytes(source, raw) == raw
        assert flat == source.read_range(0, source.size_for("vas"), view="vas")
        assert source.read_all("raw") == raw


def test_regioned_read_all_excludes_trailing_padding(padded_lldb):
    raw = padded_lldb.read_bytes()
    with open_dump(padded_lldb) as source:
        assert source.size == len(raw)  # size is the RAW size (the trap)
        flat = source.read_all()
        assert len(flat) == source.size_for("vas") == len(raw) - 0x777
        assert flat == raw[:len(flat)] == _iter_ranges_bytes(source, raw)
        assert source.read_all("raw") == raw


def test_regioned_read_all_on_the_shared_fixture(tmp_path):
    synth_raw_regions.build(tmp_path)
    for name in ("gdb_raw.bin", "lldb_raw.bin"):
        path = tmp_path / name
        with open_dump(path) as source:
            assert source.read_all() == _iter_ranges_bytes(source, path.read_bytes())


# ---------------------------------------------------------------------------
# flat-view helpers
# ---------------------------------------------------------------------------


def test_flat_view_names_the_read_all_view(gcore_dump, padded_lldb, tmp_path):
    raw_path = tmp_path / "plain.dump"
    raw_path.write_bytes(b"abc" * 100)
    with open_dump(raw_path) as raw:
        assert flat_view(raw) == "raw" and flat_view_size(raw) == 300
    for path in (gcore_dump, padded_lldb):
        with open_dump(path) as source:
            assert flat_view(source) == "vas"
            assert flat_view_size(source) == len(source.read_all())
            assert flat_view_size(source) != source.size  # raw size differs
            assert read_flat_range(source, 5, 300) == source.read_all()[5:305]


def test_flat_view_tolerates_duck_typed_sources():
    class _Fake:
        size = 8

        def read_all(self):
            return b"x" * 8

        def read_range(self, offset, length):
            return b"x" * length

    assert flat_view(_Fake()) is None and flat_view(object()) is None
    assert flat_view_size(_Fake()) == 8
    assert read_estimate_sample(_Fake()) == [b"x" * 8]


def test_estimate_sample_reads_the_flat_view(gcore_dump):
    with open_dump(gcore_dump) as source:
        assert read_estimate_sample(source) == [source.read_all()]
        blocks = read_estimate_sample(source, blocks=4, block_bytes=256)
        flat = source.read_all()
        stride = (len(flat) - 256) // 3
        assert blocks == [flat[i * stride:i * stride + 256] for i in range(4)]


# ---------------------------------------------------------------------------
# strategy selection + materialisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("budget,strategy", [
    (1 << 40, STRATEGY_BYTES), (1024, STRATEGY_SPILL),
])
def test_plan_gcore(gcore_dump, budget, strategy):
    with open_dump(gcore_dump) as source:
        plan = plan_analysis_buffer(source, budget=budget)
        assert plan.strategy == strategy
        assert plan.estimate.peak_bytes == source.size_for("vas")  # 1x


@pytest.mark.parametrize("budget,strategy", [
    (1 << 40, STRATEGY_BYTES), (1024, STRATEGY_MMAP),
])
def test_plan_regioned(regioned_dump, budget, strategy):
    with open_dump(regioned_dump) as source:
        plan = plan_analysis_buffer(source, budget=budget)
        assert plan.strategy == strategy
        assert estimate_read_all(source).peak_bytes == source.size_for("vas")


def test_plan_padded_lldb_maps_the_vas_prefix(padded_lldb):
    with open_dump(padded_lldb) as source:
        assert plan_analysis_buffer(source, budget=1024).strategy == STRATEGY_MMAP


def test_spill_gcore_equals_read_all(gcore_dump, tmp_path):
    with open_dump(gcore_dump) as source:
        out = spill_flat_view(source, tmp_path / "spill", chunk_bytes=1000)
        try:
            assert out.read_bytes() == source.read_all()
        finally:
            out.unlink()


@pytest.mark.parametrize("budget", [1 << 40, 1024])
@pytest.mark.parametrize("fixture", ["gcore_dump", "gdb_dump", "lldb_dump",
                                     "padded_lldb"])
def test_buffer_equals_read_all(request, tmp_path, fixture, budget):
    path = request.getfixturevalue(fixture)
    spill_dir = tmp_path / "spill"
    with open_dump(path) as source:
        expected = source.read_all()
        with open_analysis_buffer(source, budget=budget, spill_dir=spill_dir) as buf:
            if budget == 1024:
                assert isinstance(buf, mmap.mmap)
            assert len(buf) == len(expected) and buf[:] == expected
    assert not spill_dir.exists()


# ---------------------------------------------------------------------------
# heap peak of read_all (backs the 1x factor in estimate_read_all)
# ---------------------------------------------------------------------------

BIG = 8 * 1024 * 1024


def _peak_of_read_all(path: Path) -> Tuple[int, int]:
    with open_dump(path) as source:
        tracemalloc.start()
        try:
            data = source.read_all()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return peak, len(data)


def test_gcore_read_all_holds_one_copy(tmp_path):
    segments = [(0x400000 + i * 0x1000000, os.urandom(BIG // 4), BIG // 4)
                for i in range(4)]
    peak, size = _peak_of_read_all(_write_core(tmp_path / "big.core", segments))
    assert size == BIG
    assert peak < 1.1 * size, f"peak {peak} B for a {size} B view"


def test_regioned_read_all_holds_one_copy(tmp_path):
    run_dir = tmp_path / "big"
    run_dir.mkdir()
    (run_dir / "lldb_raw.maps").write_text(
        f"{0x10000:08x}-{0x10000 + BIG:08x} rw-p 00000000 00:00 0\n")
    (run_dir / "lldb_raw.bin").write_bytes(os.urandom(BIG))
    peak, size = _peak_of_read_all(run_dir / "lldb_raw.bin")
    assert size == BIG
    assert peak < 1.1 * size, f"peak {peak} B for a {size} B view"


# ---------------------------------------------------------------------------
# run_file end to end
# ---------------------------------------------------------------------------


def _run(dump: Path, out: Path, algorithms: Sequence[str], **extra: Any) -> Dict:
    params = {"artifact_dir": str(out), "dump_path": str(dump),
              "algorithms": list(algorithms), "user_regex": SECRET_REGEX, **extra}
    ret = run_file(params, _FakeCtx())
    return json.loads((out / ret["artifacts"][0]["relpath"]).read_text())


def _hits(report: Dict, secret_type: str) -> List[Dict]:
    return [h for h in report["libraries"][0]["hits"]
            if h["secret_type"] == secret_type]


def _all_within(hits: List[Dict], offset: int, length: int) -> bool:
    """At least one hit, and every hit inside ``[offset, offset + length)``."""
    return bool(hits) and all(
        offset <= h["offset"] and h["offset"] + h["length"] <= offset + length
        for h in hits)


def _strategy_logged(caplog) -> str:
    for rec in caplog.records:
        if rec.name == BUFFER_LOGGER:
            return rec.getMessage().split(": ", 1)[1].split(" ", 1)[0]
    return ""


@pytest.mark.parametrize("fixture,secret_vas,key_vas,low_budget_strategy", [
    ("gcore_dump", GCORE_SECRET_VAS, GCORE_KEY_VAS, STRATEGY_SPILL),
    ("gdb_dump", REGIONED_SECRET_VAS, REGIONED_KEY_VAS, STRATEGY_MMAP),
    ("lldb_dump", REGIONED_SECRET_VAS, REGIONED_KEY_VAS, STRATEGY_MMAP),
    ("padded_lldb", REGIONED_SECRET_VAS, REGIONED_KEY_VAS, STRATEGY_MMAP),
])
def test_run_file_hits_at_planted_vas_offsets(request, tmp_path, monkeypatch,
                                              caplog, fixture, secret_vas,
                                              key_vas, low_budget_strategy):
    dump = request.getfixturevalue(fixture)
    algorithms = ["user_regex", "entropy_scan"]
    caplog.set_level(logging.INFO, logger=BUFFER_LOGGER)
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "100000")
    baseline = _run(dump, tmp_path / "bytes", algorithms)
    assert _strategy_logged(caplog) == STRATEGY_BYTES
    caplog.clear()

    assert sorted(h["offset"] for h in _hits(baseline, "user_regex")) == secret_vas
    assert _all_within(_hits(baseline, "entropy_scan"), key_vas, 256)
    with open_dump(dump) as source:  # hits index the same bytes as read_all
        flat = source.read_all()
        for off in secret_vas:
            assert flat[off:off + len(SECRET)] == SECRET
            assert source.read_range(off, len(SECRET), view="vas") == SECRET

    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "0.001")
    bounded = _run(dump, tmp_path / "bounded", algorithms, force_memory=True)
    assert _strategy_logged(caplog) == low_budget_strategy
    assert bounded == baseline
    assert not (tmp_path / "bounded" / "analysis" / "spill").exists()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
