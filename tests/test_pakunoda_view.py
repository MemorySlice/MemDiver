"""Tests for the no-ISF kernel view (core/image/pakunoda_view.py) and PagingSpec.

Synthetic page tables built by hand against REAL pakunoda paging formats; the
gated real-image tests need ``MEMDIVER_IMAGE_CORPUS`` (pakunoda dumps/acquired).
"""

import dataclasses
import os
import struct
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.core.image.adapters import adapter_for_view
from memdiver.core.image.pakunoda_view import (
    Leaf, NoIsfKernelAdapter, TableWalk, captured_pieces, coalesce,
    default_kernel_va_start, paging_format_for)
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import PagingSpec, ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError, ErrorCategory

pytest.importorskip("pakunoda")
from pakunoda.probes import resolve_arch  # noqa: E402

PAGE = 0x1000
C, F = RunState.CAPTURED, RunState.FAILED


def fmt_of(arch, va_bits):
    return resolve_arch(arch).paging_format(va_bits=va_bits, page_size=PAGE)


class Tables:
    """Physical table frames: ``read_phys`` returns None for absent tables."""

    def __init__(self, fmt, order="little"):
        self.fmt, self.order = fmt, order
        self.frames = {}
        self.next = 0x1000
        self.root = self.alloc()

    def alloc(self):
        addr = self.next
        self.next += PAGE
        self.frames[addr] = bytearray((1 << self.fmt.index_bits)
                                      * self.fmt.descriptor_size)
        return addr

    def set(self, table, index, desc):
        size = self.fmt.descriptor_size
        self.frames[table][index * size:(index + 1) * size] = desc.to_bytes(size, self.order)

    def read_phys(self, addr, n):
        frame = self.frames.get(addr)
        return None if frame is None else bytes(frame[:n])

    def table_for(self, va, level):
        """Walk/create table pointers down to ``level`` for canonical-or-low ``va``."""
        fmt, table = self.fmt, self.root
        va &= (1 << fmt.va_bits) - 1
        for lv in range(level):
            idx = (va >> fmt.level_shift(lv)) & ((1 << fmt.index_bits) - 1)
            raw = int.from_bytes(self.frames[table][idx * fmt.descriptor_size:
                                                    (idx + 1) * fmt.descriptor_size], self.order)
            if not raw & 1:
                nxt = self.alloc()
                self.set(table, idx, nxt | 0x3)
                table = nxt
            else:
                table = raw & fmt.pa_mask
        return table, (va >> fmt.level_shift(level)) & ((1 << fmt.index_bits) - 1)

    def map(self, va, level, desc):
        table, idx = self.table_for(va, level)
        self.set(table, idx, desc)

    def map_4k(self, va, phys, desc_flags=0x3):
        self.map(va, self.fmt.levels - 1, phys | desc_flags)


def walk(tables, va_start, runs, endian="little"):
    return list(TableWalk(tables.fmt, tables.root, endian, va_start, tables.read_phys,
                          captured_pieces(runs)).leaves())


def run(start, length):
    return LayerRun(start, length, C)


# ---------------------------------------------------------------- x86_64 -----
X86_BASE = 0xFFFF800000000000


def test_x86_64_48_leaf_kinds_and_states():
    t = Tables(fmt_of("x86_64", 48))
    # user-half entries (index < 256) must be ignored
    t.map_4k(0x7F0000000000, 0x5000)
    t.map_4k(X86_BASE + 0x0000, 0x5000)
    t.map_4k(X86_BASE + 0x1000, 0x6000)
    t.map_4k(X86_BASE + 0x2000, 0x50000000)                 # frame outside the image
    t.map(X86_BASE + 0x200000, 2, 0x200000 | 0x83)          # 2M, half captured
    pd, _ = t.table_for(X86_BASE + 0x400000, 2)
    t.set(pd, 2, 0x9000 | 0x3)                              # table pointer, frame absent
    t.set(pd, 3, 0x0)                                       # not present
    t.map(X86_BASE + (1 << 30), 1, 0x40000000 | 0x83)       # 1G page, not captured
    runs = [run(0, 0x10000), run(0x200000, 0x100000)]
    got = walk(t, X86_BASE, runs)
    assert got == [
        Leaf(X86_BASE + 0x0000, 0x1000, 0x5000, C),
        Leaf(X86_BASE + 0x1000, 0x1000, 0x6000, C),
        Leaf(X86_BASE + 0x2000, 0x1000, 0x50000000, F),
        Leaf(X86_BASE + 0x200000, 0x100000, 0x200000, C),
        Leaf(X86_BASE + 0x300000, 0x100000, 0x300000, F),
        Leaf(X86_BASE + 0x400000, 0x200000, None, F),
        Leaf(X86_BASE + (1 << 30), 1 << 30, 0x40000000, F),
    ]
    assert all(leaf.va >= 0xFFFF800000000000 for leaf in got)   # canonical, no user VAs


def test_x86_64_user_half_only_yields_nothing():
    t = Tables(fmt_of("x86_64", 48))
    t.map_4k(0x1000, 0x5000)
    assert walk(t, default_kernel_va_start("x86_64", 48), [run(0, 0x10000)]) == []


def test_x86_64_57_five_level_canonical_va():
    t = Tables(fmt_of("x86_64", 57))
    va = 0xFF00000000000000 + 0x3000
    t.map_4k(va, 0x7000)
    assert default_kernel_va_start("x86_64", 57) == 0xFF00000000000000
    assert walk(t, default_kernel_va_start("x86_64", 57), [run(0, 0x10000)]) == [
        Leaf(va, 0x1000, 0x7000, C)]


def test_kernel_va_start_override_is_honored():
    t = Tables(fmt_of("x86_64", 48))
    lo, hi = X86_BASE + (5 << 39), X86_BASE + (7 << 39)
    t.map_4k(lo, 0x5000)
    t.map_4k(hi, 0x6000)
    runs = [run(0, 0x10000)]
    assert [x.va for x in walk(t, X86_BASE, runs)] == [lo, hi]
    assert [x.va for x in walk(t, X86_BASE + (6 << 39), runs)] == [hi]


def test_default_kernel_va_start_per_architecture():
    assert default_kernel_va_start("x86_64", 48) == 0xFFFF800000000000
    assert default_kernel_va_start("aarch64", 48) == 0xFFFF000000000000
    assert default_kernel_va_start("arm64", 39) == 0xFFFFFF8000000000
    assert default_kernel_va_start("x86_32", 32) == 0xC0000000
    assert default_kernel_va_start(None, 32) == 0xC0000000


def test_x86_32_style_explicit_format_big_endian():
    from pakunoda.core.pagetable import PagingFormat
    fmt = PagingFormat(levels=2, page_shift=12, index_bits=10, descriptor_size=4,
                       pa_mask=0xFFFFF000, leaf_flag_mask=0x80, leaf_when_set=True)
    for order in ("little", "big"):
        t = Tables(fmt, order)
        t.map_4k(0xC0001000, 0x5000)
        t.map_4k(0x00001000, 0x6000)            # user side, below the 3G split
        got = walk(t, default_kernel_va_start("x86_32", 32), [run(0, 0x10000)], order)
        assert got == [Leaf(0xC0001000, 0x1000, 0x5000, C)], order


# --------------------------------------------------------------- aarch64 -----
def test_aarch64_48_page_block_and_reserved():
    t = Tables(fmt_of("aarch64", 48))
    base = 0xFFFF000000000000
    t.map_4k(base + 0x0000, 0x5000)
    t.map_4k(base + 0x1000, 0x6000, 0x1)                    # reserved last-level: dropped
    t.map_4k(base + 0x2000, 0x50000000)                     # frame outside the image
    t.map(base + 0x200000, 2, 0x200000 | 0x1)               # 2M block (bit1 clear)
    t.map(base + (1 << 30), 1, 0x40000000 | 0x1)            # 1G block
    runs = [run(0, 0x10000), run(0x200000, 0x100000)]
    assert walk(t, base, runs) == [
        Leaf(base + 0x0000, 0x1000, 0x5000, C),
        Leaf(base + 0x2000, 0x1000, 0x50000000, F),
        Leaf(base + 0x200000, 0x100000, 0x200000, C),
        Leaf(base + 0x300000, 0x100000, 0x300000, F),
        Leaf(base + (1 << 30), 1 << 30, 0x40000000, F),
    ]


def test_aarch64_39_three_level():
    t = Tables(fmt_of("aarch64", 39))
    base = default_kernel_va_start("aarch64", 39)
    t.map_4k(base + 0x4000, 0x8000)
    t.map(base + 0x200000, 1, 0x200000 | 0x1)
    assert walk(t, base, [run(0, 0x10000), run(0x200000, 0x200000)]) == [
        Leaf(base + 0x4000, 0x1000, 0x8000, C),
        Leaf(base + 0x200000, 0x200000, 0x200000, C)]


def test_missing_root_table_is_one_failed_leaf_for_the_kernel_half():
    t = Tables(fmt_of("x86_64", 48))
    t.frames.clear()
    assert walk(t, X86_BASE, []) == [Leaf(X86_BASE, 256 << 39, None, F)]


# ------------------------------------------------------ coalesce / pieces ----
def test_coalesce_merges_only_adjacent_same_state():
    leaves = [Leaf(0x0, 0x1000, 0x9000, C), Leaf(0x1000, 0x1000, 0x1000, C),   # scattered phys
              Leaf(0x2000, 0x1000, None, F), Leaf(0x3000, 0x1000, 0x5000, F),
              Leaf(0x5000, 0x1000, 0x6000, F),                                # VA gap
              Leaf(0x6000, 0x1000, 0x7000, C)]
    assert coalesce(leaves) == [LayerRun(0, 0x2000, C), LayerRun(0x2000, 0x2000, F),
                                LayerRun(0x5000, 0x1000, F), LayerRun(0x6000, 0x1000, C)]
    assert coalesce([]) == []


RUNS = [run(0x1000, 0x1000), run(0x3000, 0x2000)]


@pytest.mark.parametrize("phys,size,expected", [
    (0x0, 0x800, [(0x0, 0x800, False)]),                                   # before all
    (0x0, 0x1000, [(0x0, 0x1000, False)]),                                 # ends at run start
    (0x1000, 0x1000, [(0x1000, 0x1000, True)]),                            # exact run
    (0x800, 0x1000, [(0x800, 0x800, False), (0x1000, 0x800, True)]),
    (0x1800, 0x2000, [(0x1800, 0x800, True), (0x2000, 0x1000, False),
                      (0x3000, 0x800, True)]),                             # spans the gap
    (0x2000, 0x1000, [(0x2000, 0x1000, False)]),                           # entirely in gap
    (0x4000, 0x2000, [(0x4000, 0x1000, True), (0x5000, 0x1000, False)]),   # off the end
    (0x9000, 0x1000, [(0x9000, 0x1000, False)]),                           # after all
])
def test_captured_pieces(phys, size, expected):
    assert list(captured_pieces(RUNS)(phys, size)) == expected


def test_captured_pieces_no_runs_and_pieces_tile_the_range():
    assert list(captured_pieces([])(0x1000, 0x1000)) == [(0x1000, 0x1000, False)]
    pieces = list(captured_pieces(RUNS)(0x500, 0x5000))
    assert sum(p[1] for p in pieces) == 0x5000
    assert all(a[0] + a[1] == b[0] for a, b in zip(pieces, pieces[1:]))


# ------------------------------------------------- PagingSpec / format -------
def test_paging_spec_round_trip_and_old_dicts():
    spec = PagingSpec(pgd_phys=0x1000, arch="aarch64", va_bits=39, endian="big",
                      format={"levels": 3}, kernel_va_start=0xFFFF000000000000)
    assert PagingSpec.from_dict(spec.to_dict()) == spec
    old = PagingSpec.from_dict({"pgd_phys": 5, "arch": "x86_64", "va_bits": 48, "page_size": 4096})
    assert (old.endian, old.format, old.kernel_va_start) == ("little", None, None)
    assert old.pgd_phys == 5


def test_paging_format_for_arch_and_errors():
    fmt = paging_format_for(PagingSpec(arch="x86_64", va_bits=57))
    assert fmt.levels == 5
    with pytest.raises(CapabilityError) as e:
        paging_format_for(PagingSpec())
    assert e.value.category is ErrorCategory.INVALID_INPUT
    with pytest.raises(CapabilityError) as e:
        paging_format_for(PagingSpec(format={"bogus": 1}))
    assert e.value.category is ErrorCategory.INVALID_INPUT
    with pytest.raises(CapabilityError) as e:       # ValueError from the format's own guards
        paging_format_for(PagingSpec(format=dict(levels=2, page_shift=12, index_bits=9,
                                                 descriptor_size=3, pa_mask=0xFFFFF000,
                                                 leaf_flag_mask=0x80, leaf_when_set=True)))
    assert e.value.category is ErrorCategory.INVALID_INPUT


# ---------------------------------------------------- adapter, fake image ----
class FakeLayer:
    """Sparse physical layer: ``blocks`` = {start: bytes}; reads never pad."""

    def __init__(self, blocks):
        self.blocks = blocks
        self.maximum_address = max(s + len(b) for s, b in blocks.items()) - 1
        self.pad_seen = []

    def _find(self, addr, n):
        for s, b in self.blocks.items():
            if s <= addr and addr + n <= s + len(b):
                return s, b
        return None

    def is_valid(self, addr, n=1):
        return self._find(addr, n) is not None

    def read(self, addr, n, pad=False):
        self.pad_seen.append(pad)
        hit = self._find(addr, n)
        if hit is None:
            raise IndexError(f"{addr:#x} not mapped")
        s, b = hit
        return bytes(b[addr - s:addr - s + n])

    def mapping(self, offset, length, ignore_errors=False):
        return [(s, len(b), s, len(b), "base") for s, b in sorted(self.blocks.items())]


def fake_image(layer):
    return SimpleNamespace(lock=threading.RLock(), physical_layer="phys",
                           context=SimpleNamespace(layers={"phys": layer}))


@pytest.fixture
def scattered():
    """Kernel pages: VA +0/+1000 adjacent but physically scattered; +2000 FAILED;
    +4000 captured after a VA hole."""
    fmt = fmt_of("x86_64", 48)
    t = Tables(fmt)
    data = {0x10000: bytes([1]) * PAGE, 0x8000: bytes([2]) * PAGE,
            0x105000: bytes([3]) * PAGE}
    t.map_4k(X86_BASE + 0x0000, 0x10000)
    t.map_4k(X86_BASE + 0x1000, 0x8000)
    t.map_4k(X86_BASE + 0x2000, 0x50000000)
    t.map_4k(X86_BASE + 0x4000, 0x105000)
    low = bytearray(0x20000)
    for addr, frame in t.frames.items():
        low[addr:addr + PAGE] = frame
    low[0x10000:0x11000] = data[0x10000]
    low[0x8000:0x9000] = data[0x8000]
    # make the first and last bytes of each page distinguishable
    low[0x10FFF] = 0xAA
    low[0x8000] = 0xBB
    high = bytearray(0x10000)
    high[0x5000:0x6000] = data[0x105000][:PAGE]
    layer = FakeLayer({0: bytes(low), 0x100000: bytes(high)})
    spec = PagingSpec(pgd_phys=t.root, arch="x86_64", va_bits=48)
    return NoIsfKernelAdapter(fake_image(layer), spec), layer, t


def test_adapter_runs_are_coalesced_by_state(scattered):
    adapter, _, _ = scattered
    assert list(adapter.runs()) == [LayerRun(X86_BASE, 0x2000, C),
                                    LayerRun(X86_BASE + 0x2000, 0x1000, F),
                                    LayerRun(X86_BASE + 0x4000, 0x1000, C)]


def test_adapter_read_crosses_physically_scattered_leaves(scattered):
    adapter, layer, _ = scattered
    got = adapter.read(X86_BASE + 0xFFF, 2)
    assert got == bytes([0xAA, 0xBB])                         # end of 0x10000 page, start of 0x8000
    assert adapter.read(X86_BASE + 0x800, 0x1000)[0x7FF:0x801] == bytes([0xAA, 0xBB])
    assert adapter.read(X86_BASE, 0) == b""
    assert set(layer.pad_seen) == {False}                     # never padded


@pytest.mark.parametrize("offset,length", [
    (0x2000, 1),            # FAILED leaf
    (0x1FFF, 2),            # starts captured, runs into FAILED
    (0x3000, 1),            # VA hole
    (-0x1000, 1),           # below every leaf
    (0x5000, 1),            # past the last leaf
])
def test_adapter_read_of_uncaptured_va_raises_never_zeros(scattered, offset, length):
    adapter, _, _ = scattered
    with pytest.raises(CapabilityError) as e:
        adapter.read(X86_BASE + offset, length)
    assert e.value.category is ErrorCategory.INVALID_INPUT


def test_adapter_translate_and_describe(scattered):
    adapter, _, t = scattered
    assert adapter.translate(X86_BASE + 0x1010) == 0x8010
    assert adapter.translate(X86_BASE + 0x2000) is None       # FAILED
    assert adapter.translate(X86_BASE + 0x3000) is None       # unmapped
    assert adapter.translate(X86_BASE - 1) is None
    info = adapter.describe()
    assert info["view"] == "kernel" and info["profile"] is None
    assert (info["levels"], info["va_bits"]) == (4, 48)
    assert info["kernel_va_start"] == hex(X86_BASE)
    assert info["leaves"] == 4
    assert info["paging"]["pgd_phys"] == t.root
    adapter.close()


def test_adapter_describe_leaves_none_before_first_walk():
    t = Tables(fmt_of("x86_64", 48))
    layer = FakeLayer({0: bytes(0x4000)})
    spec = PagingSpec(pgd_phys=t.root, arch="x86_64", va_bits=48)
    assert NoIsfKernelAdapter(fake_image(layer), spec).describe()["leaves"] is None


def test_adapter_requires_pgd_phys():
    layer = FakeLayer({0: bytes(0x1000)})
    for spec in (PagingSpec(arch="x86_64", va_bits=48), None):
        with pytest.raises(CapabilityError) as e:
            NoIsfKernelAdapter(fake_image(layer), spec)
        assert e.value.category is ErrorCategory.INVALID_INPUT


def test_adapter_explicit_format_dict_and_invalid_format():
    fmt = fmt_of("aarch64", 48)
    t = Tables(fmt)
    base = 0xFFFF000000000000
    t.map_4k(base + 0x1000, 0x6000)
    low = bytearray(0x10000)
    for addr, frame in t.frames.items():
        low[addr:addr + PAGE] = frame
    low[0x6000:0x6004] = b"ABCD"
    layer = FakeLayer({0: bytes(low)})
    spec = PagingSpec(pgd_phys=t.root, arch="aarch64", va_bits=48,
                      format=dataclasses.asdict(fmt), kernel_va_start=base)
    adapter = NoIsfKernelAdapter(fake_image(layer), spec)
    assert adapter.read(base + 0x1000, 4) == b"ABCD"
    with pytest.raises(CapabilityError) as e:
        NoIsfKernelAdapter(fake_image(layer), PagingSpec(pgd_phys=1, format={"levels": 1}))
    assert e.value.category is ErrorCategory.INVALID_INPUT


def test_adapter_for_view_routes_profileless_kernel_to_noisf(scattered):
    adapter, layer, t = scattered
    desc = ViewDescriptor("x.lime", "ab" * 32, ViewKind.KERNEL,
                          paging=PagingSpec(pgd_phys=t.root, arch="x86_64", va_bits=48))
    routed = adapter_for_view(fake_image(layer), desc)
    assert isinstance(routed, NoIsfKernelAdapter)
    assert routed.read(X86_BASE + 0x1000, 1) == bytes([0xBB])


def test_adapter_for_view_without_pgd_phys_is_capability_error(scattered):
    _, layer, _ = scattered
    desc = ViewDescriptor("x.lime", "ab" * 32, ViewKind.KERNEL,
                          paging=PagingSpec(arch="x86_64", va_bits=48))
    with pytest.raises(CapabilityError):
        adapter_for_view(fake_image(layer), desc)


def test_mdview_descriptor_round_trips_new_paging_fields(tmp_path):
    spec = PagingSpec(pgd_phys=0x1000, arch="aarch64", va_bits=48, endian="little",
                      kernel_va_start=0xFFFF000000000000)
    path = ViewDescriptor("x.lime", "ab" * 32, ViewKind.KERNEL, paging=spec).write(
        tmp_path / "k.mdview")
    assert ViewDescriptor.read(path).paging == spec


# ----------------------------------------------------- gated real image ------
_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
CORPUS = Path(_ROOT) if _ROOT else None
ARISTA = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"


def _has_arista():
    return CORPUS is not None and all((CORPUS / f"{ARISTA}{ext}").is_file()
                                      for ext in (".lime", ".isf.json"))


real = pytest.mark.skipif(
    not _has_arista(), reason="set MEMDIVER_IMAGE_CORPUS to a dir with the arista-eos .lime + .isf.json")


@pytest.fixture(scope="module")
def arista(tmp_path_factory):
    from memdiver.core.image.context import ImageContext
    from pakunoda import probes
    image, isf = CORPUS / f"{ARISTA}.lime", CORPUS / f"{ARISTA}.isf.json"
    root = probes.find_page_table_root(probes.open_dump(image), probes.resolve_arch("x86_64"))
    assert root is not None and root.verified
    ctx_isf = ImageContext.build(image, isf)
    sym = ctx_isf.kernel.get_absolute_symbol_address("linux_banner")
    return SimpleNamespace(image=image, root=root, ctx_isf=ctx_isf,
                           banner_va=ctx_isf.canonical_kernel_va(sym),
                           ctx_plain=ImageContext.build(image))


def _spec(root):
    return PagingSpec(pgd_phys=root.pgd_phys, arch="x86_64", va_bits=root.va_bits)


@real
def test_real_noisf_banner_matches_isf_view(arista):
    from memdiver.core.image.adapters import KernelAdapter
    adapter = NoIsfKernelAdapter(arista.ctx_plain, _spec(arista.root))
    t0 = time.monotonic()
    runs = adapter.runs()
    assert time.monotonic() - t0 < 5
    assert any(r.state is C for r in runs)
    got = adapter.read(arista.banner_va, 64)
    assert got.startswith(b"Linux version")
    assert got == KernelAdapter(arista.ctx_isf).read(arista.banner_va, 64)
    assert adapter.translate(arista.banner_va) is not None


@real
def test_real_mdview_through_dump_source(arista, tmp_path, monkeypatch):
    from memdiver.core.dump_source import open_dump
    from memdiver.core.image.context import file_sha256
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    desc = ViewDescriptor(image=str(arista.image), image_sha256=file_sha256(arista.image),
                          view=ViewKind.KERNEL, paging=_spec(arista.root))
    path = desc.write(tmp_path / "arista.mdview")
    with open_dump(path) as src:
        result = src.read_location(arista.banner_va, 64)
        assert result.data.startswith(b"Linux version")
        assert result.coverage.captured == result.coverage.requested == 64


# ------------------------------------------------ review-fix regressions ----
@pytest.mark.parametrize("arch", ["x86_64", "aarch64", "arm64"])
def test_ambiguous_arch_without_va_bits_is_refused(arch):
    with pytest.raises(CapabilityError) as e:
        paging_format_for(PagingSpec(pgd_phys=1, arch=arch))
    assert e.value.code == "paging_va_bits_required"
    assert e.value.category is ErrorCategory.INVALID_INPUT


def test_explicit_format_needs_no_va_bits():
    fmt = fmt_of("x86_64", 48)
    spec = PagingSpec(pgd_phys=1, arch="x86_64", format=dataclasses.asdict(fmt)) \
        if dataclasses.is_dataclass(fmt) else None
    if spec is not None:
        assert paging_format_for(spec).levels == 4


def test_walk_budget_leaves_and_tables():
    t = Tables(fmt_of("x86_64", 48))
    for i in range(8):
        t.map_4k(X86_BASE + i * PAGE, 0x5000)
    runs = [run(0, 0x10000)]
    with pytest.raises(CapabilityError) as e:
        list(TableWalk(t.fmt, t.root, "little", X86_BASE, t.read_phys,
                       captured_pieces(runs), max_leaves=4).leaves())
    assert e.value.code == "paging_walk_budget" and e.value.details["limit"] == "leaves"
    with pytest.raises(CapabilityError) as e:
        list(TableWalk(t.fmt, t.root, "little", X86_BASE, t.read_phys,
                       captured_pieces(runs), max_tables=2).leaves())
    assert e.value.details["limit"] == "tables read"


def test_describe_kernel_va_start_is_hex_string(scattered):
    adapter, _, _ = scattered
    assert adapter.describe()["kernel_va_start"] == "0xffff800000000000"


def test_concurrent_first_read_walks_once_and_sees_captured(scattered):
    adapter, layer, _ = scattered
    gate, entered, walks = threading.Event(), threading.Event(), []
    real = adapter._walk_leaves

    def slow():
        walks.append(1)
        entered.set()
        gate.wait(5)
        return real()
    adapter._walk_leaves = slow
    got = []
    first = threading.Thread(target=lambda: got.append(adapter.runs()))
    first.start()
    assert entered.wait(5)
    assert adapter._leaves is None and adapter._starts == []     # nothing half-published
    second = threading.Thread(target=lambda: got.append(adapter.read(X86_BASE, 1)))
    second.start()
    time.sleep(0.1)
    gate.set()
    first.join(5)
    second.join(5)
    assert len(walks) == 1 and bytes([1]) in got
