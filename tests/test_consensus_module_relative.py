"""S4: ``module_relative`` alignment for independently launched process views.

Two fake "processes" map the same program (exe + its .bss, libc, heap, one
anonymous mmap) at DIFFERENT ASLR bases. Absolute-VA keys line up nothing;
module-relative keys line up every module / .bss / heap page and leave the
anonymous mmap out (counted, never compared). Also covers the dispatch rules,
the explicit override, and the image-EXTRACTED ``.msl`` that used to fall to
``file_offset``.
"""

from __future__ import annotations

from typing import List, Tuple

import numpy as np
import pytest

from memdiver.core.dump_source import RawDumpSource, open_dump
from memdiver.core.image.adapters import Vma
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.module_relative import (
    MODULE_RELATIVE_UNKEYED,
    AlignmentVma,
    ModuleRelativeKeyer,
    alignment_vmas,
    is_image_extracted_msl,
    layouts_differ,
)
from memdiver.core.region_align import (
    ALIGNMENT_MODULE_RELATIVE,
    build_va_page_index,
)
from memdiver.core.service_errors import CapabilityError
from memdiver.core.variance import ByteClass
from memdiver.engine.consensus import (
    ALIGNMENT_FILE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
    ConsensusVector,
    choose_alignment,
)
from memdiver.engine.consensus_service import build_consensus
from memdiver.msl.image_extract import extract_process_to_msl

P = 0x1000
EXE, LIBC = "/usr/bin/app", "/usr/lib/libc.so.6"
#: (name, logical id, pages, file_backed, is_heap, offset from the layout base)
_PLAN = [
    (EXE, "exe0", 2, True, False, 0x0),
    (EXE, "exe1", 1, True, False, 2 * P),
    ("", "bss", 1, False, False, 3 * P),          # .bss: adjacent to exe's last VMA
    ("[heap]", "heap", 2, False, True, 0x100000),
    (LIBC, "libc", 2, True, False, 0x10000000),
    ("", "mmap", 1, False, False, 0x20000000),    # plain anon: no stable key
]
SECRET_PAGE = "heap"


def _layout(base: int) -> List[Tuple[Vma, str]]:
    return [(Vma(base + off, base + off + n * P, name, "rw-", heap, fb), logical)
            for name, logical, n, fb, heap, off in _PLAN]


def _content(logical: str, offset: int, process: int, secret: bool) -> int:
    if secret and logical == SECRET_PAGE and offset < 32:
        return (process * 97 + offset * 13 + 5) % 256
    return (sum(map(ord, logical)) * 7 + offset * 3) % 251


class _FakeProcess:
    """A process adapter whose bytes depend on (logical VMA, offset), not VA."""

    def __init__(self, base: int, process: int, secret: bool) -> None:
        self._vmas = _layout(base)
        self._process, self._secret = process, secret

    def vmas(self):
        return [v for v, _ in self._vmas]

    def runs(self):
        return [LayerRun(v.start, v.end - v.start, RunState.CAPTURED)
                for v, _ in self._vmas]

    def read(self, address, length):
        return bytes(self._byte(a) for a in range(address, address + length))

    def _byte(self, va):
        for vma, logical in self._vmas:
            if vma.start <= va < vma.end:
                return _content(logical, va - vma.start, self._process, self._secret)
        raise AssertionError(f"read outside every VMA: {va:#x}")

    def describe(self):
        return {"view": "process", "pid": 100 + self._process, "comm": "app"}

    def close(self):
        pass


BASE_A, BASE_B = 0x555500000000, 0x561234560000


def _view(tmp_path, name, base, process, *, secret=False) -> Vol3LayerSource:
    (tmp_path / "img.lime").write_bytes(b"\x00" * 64)
    desc = ViewDescriptor("img.lime", "ab" * 32, ViewKind.PROCESS,
                          pid=100 + process, profile=ProfileRef("p.json"))
    path = desc.write(tmp_path / f"{name}.mdview")
    adapter = _FakeProcess(base, process, secret)
    src = Vol3LayerSource(path, adapter_factory=lambda d, p: adapter)
    src.open()
    return src


def _build(sources, **kw) -> ConsensusVector:
    cm = ConsensusVector()
    try:
        cm.build_from_sources(sources, **kw)
    finally:
        for s in sources:
            s.close()
    return cm


KEYED_BYTES = 8 * P      # exe 3 + bss 1 + heap 2 + libc 2
TOTAL_BYTES = 9 * P      # + the dropped anonymous mmap page


# ---------------------------------------------------------------------------
# Key function
# ---------------------------------------------------------------------------

def _avmas(base) -> List[AlignmentVma]:
    return [AlignmentVma(v.start, v.end, v.name, v.file_backed, v.is_heap)
            for v, _ in _layout(base)]


@pytest.mark.parametrize("base", [BASE_A, BASE_B])
def test_keys_are_module_relative_and_base_independent(base):
    key = ModuleRelativeKeyer(_avmas(base))
    assert key(base) == f"mod:{EXE}:0x000000000000"
    assert key(base + 2 * P + 8) == f"mod:{EXE}:0x000000002008"
    assert key(base + 3 * P) == f"mod:{EXE}:bss:+0x000000000000"
    assert key(base + 0x100000 + P) == "heap:+0x000000001000"
    assert key(base + 0x10000000) == f"mod:{LIBC}:0x000000000000"
    assert key(base + 0x20000000) is None          # anonymous mmap: unkeyed
    assert key(base - 1) is None and key(base + 0x30000000) is None


def test_anon_not_adjacent_to_a_modules_last_vma_is_not_bss():
    vmas = [AlignmentVma(0x1000, 0x2000, EXE, True, False),
            AlignmentVma(0x2000, 0x3000, "", False, False),   # between exe VMAs
            AlignmentVma(0x3000, 0x4000, EXE, True, False),
            AlignmentVma(0x5000, 0x6000, "", False, False)]   # gap before it
    key = ModuleRelativeKeyer(vmas)
    assert key(0x2000) is None and key(0x5000) is None
    assert key(0x3000) == f"mod:{EXE}:0x000000002000"


def test_unresolved_file_names_never_key():
    key = ModuleRelativeKeyer([AlignmentVma(0x1000, 0x2000, "<unresolved>", True, False)])
    assert key(0x1000) is None


def test_layouts_differ_only_on_a_common_module_at_different_bases():
    assert layouts_differ([_avmas(BASE_A), _avmas(BASE_B)])
    assert not layouts_differ([_avmas(BASE_A), _avmas(BASE_A)])
    lone = [AlignmentVma(0x9000, 0xA000, "/other", True, False)]
    assert not layouts_differ([_avmas(BASE_A), lone])


def test_page_index_counts_unkeyed_bytes(tmp_path):
    src = _view(tmp_path, "a", BASE_A, 0)
    try:
        ix = build_va_page_index(0, src, keying=ALIGNMENT_MODULE_RELATIVE)
    finally:
        src.close()
    assert ix.unkeyed_bytes == P
    assert len(ix.region_map.regions) == KEYED_BYTES // P
    # source_base_addr stays this dump's real VA
    region = ix.region_map.regions["heap:+0x000000000000"]
    assert region.source_base_addr == BASE_A + 0x100000


def test_page_index_refuses_module_relative_without_vmas(tmp_path):
    p = tmp_path / "r.dump"
    p.write_bytes(b"\x00" * P)
    src = RawDumpSource(p)
    with pytest.raises(ValueError, match="no VMA listing"):
        build_va_page_index(0, src, keying=ALIGNMENT_MODULE_RELATIVE)


# ---------------------------------------------------------------------------
# End-to-end consensus
# ---------------------------------------------------------------------------

def test_independent_processes_align_module_relative_and_are_invariant(tmp_path):
    cm = _build([_view(tmp_path, "a", BASE_A, 0), _view(tmp_path, "b", BASE_B, 1)])
    report = cm.alignment_report
    assert report.method == ALIGNMENT_MODULE_RELATIVE
    assert report.bytes_compared == KEYED_BYTES
    assert report.bytes_discarded == 2 * P            # one anon page per dump
    codes = [d.code for d in report.diagnostics]
    assert MODULE_RELATIVE_UNKEYED in codes
    unkeyed = next(d for d in report.diagnostics if d.code == MODULE_RELATIVE_UNKEYED)
    assert unkeyed.details["unkeyed_bytes"] == [P, P]
    assert cm.classification_counts() == {"invariant": KEYED_BYTES}
    # every layout row carries each dump's OWN VA for the same logical page
    for _slab, _ps, vaddrs in cm.msl_layout:
        assert vaddrs[1] - vaddrs[0] == BASE_B - BASE_A


def test_differing_bytes_are_classified_at_the_module_relative_spot(tmp_path):
    cm = _build([_view(tmp_path, "a", BASE_A, 0, secret=True),
                 _view(tmp_path, "b", BASE_B, 1, secret=True)])
    assert cm.alignment_report.method == ALIGNMENT_MODULE_RELATIVE
    classes = np.asarray(cm.classifications)
    varying = np.flatnonzero(classes != int(ByteClass.INVARIANT))
    assert 0 < len(varying) <= 32
    heap_va = BASE_A + 0x100000
    slab = next(s for s, _ps, v in cm.msl_layout if v[0] == heap_va)
    assert set(varying.tolist()) <= set(range(slab, slab + 32))


def test_absolute_va_would_have_aligned_nothing(tmp_path):
    """The before-picture the new regime fixes (explicit override)."""
    cm = _build([_view(tmp_path, "a", BASE_A, 0), _view(tmp_path, "b", BASE_B, 1)],
                alignment=ALIGNMENT_VIRTUAL_ADDRESS)
    assert cm.alignment_report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert cm.alignment_report.bytes_compared == 0


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_identical_layouts_keep_virtual_address(tmp_path):
    """Forked siblings: same layout -> absolute VA, anonymous memory included."""
    cm = _build([_view(tmp_path, "a", BASE_A, 0), _view(tmp_path, "b", BASE_A, 1)])
    report = cm.alignment_report
    assert report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert report.bytes_compared == TOTAL_BYTES
    assert report.bytes_discarded == 0
    assert report.diagnostics == ()


def test_explicit_module_relative_on_identical_layouts(tmp_path):
    cm = _build([_view(tmp_path, "a", BASE_A, 0), _view(tmp_path, "b", BASE_A, 1)],
                alignment=ALIGNMENT_MODULE_RELATIVE)
    assert cm.alignment_report.method == ALIGNMENT_MODULE_RELATIVE
    assert cm.alignment_report.bytes_compared == KEYED_BYTES


def test_explicit_module_relative_is_refused_for_sources_without_vmas(tmp_path):
    sources = []
    for i in range(2):
        p = tmp_path / f"r{i}.dump"
        p.write_bytes(b"\x01" * P)
        src = RawDumpSource(p)
        src.open()
        sources.append(src)
    with pytest.raises(CapabilityError) as err:
        _build(sources, alignment=ALIGNMENT_MODULE_RELATIVE)
    assert err.value.code == "consensus.alignment_unavailable"


def test_unknown_alignment_is_refused_before_reading(tmp_path):
    with pytest.raises(CapabilityError) as err:
        ConsensusVector().build_from_sources([], alignment="nonsense")
    assert err.value.code == "consensus.unknown_alignment"
    with pytest.raises(CapabilityError):
        build_consensus([tmp_path / "missing.dump"] * 2, alignment="nonsense")


def test_auto_on_raw_inputs_is_unchanged(tmp_path):
    """Regression pin: raw dumps never see the new regime."""
    sources = []
    for i, blob in enumerate((b"\x01" * (2 * P), b"\x01" * P + b"\x02" * P)):
        p = tmp_path / f"raw{i}.dump"
        p.write_bytes(blob)
        src = RawDumpSource(p)
        src.open()
        sources.append(src)
    assert choose_alignment(sources) == ALIGNMENT_FILE_OFFSET
    cm = _build(sources)
    assert cm.alignment_report.method == ALIGNMENT_FILE_OFFSET
    assert cm.alignment_report.bytes_compared == 2 * P
    assert cm.classification_counts()["invariant"] == P


# ---------------------------------------------------------------------------
# Image-extracted .msl (item B)
# ---------------------------------------------------------------------------

def _extracted(tmp_path, name, base, process, *, secret=False):
    view = _view(tmp_path, f"{name}_view", base, process, secret=secret)
    out = tmp_path / f"{name}.msl"
    try:
        extract_process_to_msl(view, out, note_fields={"image_sha256": "ab" * 32})
    finally:
        view.close()
    return out


def _open_all(paths):
    sources = [open_dump(p) for p in paths]
    for s in sources:
        s.open()
    return sources


def test_extracted_msl_is_recognised_and_lists_its_vmas(tmp_path):
    (src,) = _open_all([_extracted(tmp_path, "x", BASE_A, 0)])
    try:
        assert is_image_extracted_msl(src)
        vmas = alignment_vmas(src)
        assert vmas is not None
        assert {v.name for v in vmas if v.file_backed} == {EXE, LIBC}
        assert [v.start for v in vmas if v.is_heap] == [BASE_A + 0x100000]
    finally:
        src.close()


def test_extracted_msl_pair_same_layout_aligns_by_va_not_file_offset(tmp_path):
    paths = [_extracted(tmp_path, "x", BASE_A, 0), _extracted(tmp_path, "y", BASE_A, 1)]
    cm = _build(_open_all(paths))
    assert cm.alignment_report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert cm.alignment_report.bytes_compared == TOTAL_BYTES


def test_extracted_msl_pair_independent_layouts_align_module_relative(tmp_path):
    paths = [_extracted(tmp_path, "x", BASE_A, 0, secret=True),
             _extracted(tmp_path, "y", BASE_B, 1, secret=True)]
    cm = _build(_open_all(paths))
    report = cm.alignment_report
    assert report.method == ALIGNMENT_MODULE_RELATIVE
    assert report.bytes_compared == KEYED_BYTES
    counts = cm.classification_counts()
    assert counts.get("invariant", 0) >= KEYED_BYTES - 32


def test_extracted_msl_beside_an_independent_view_aligns_module_relative(tmp_path):
    msl = _extracted(tmp_path, "x", BASE_A, 0)
    sources = _open_all([msl]) + [_view(tmp_path, "b", BASE_B, 1)]
    cm = _build(sources)
    assert cm.alignment_report.method == ALIGNMENT_MODULE_RELATIVE
    assert cm.classification_counts() == {"invariant": KEYED_BYTES}


def test_build_consensus_threads_the_override(tmp_path):
    paths = [_extracted(tmp_path, "x", BASE_A, 0), _extracted(tmp_path, "y", BASE_B, 1)]
    auto = build_consensus(paths, allocator="off")
    forced = build_consensus(paths, allocator="off", alignment=ALIGNMENT_VIRTUAL_ADDRESS)
    assert auto.alignment_report.method == ALIGNMENT_MODULE_RELATIVE
    assert forced.alignment_report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert forced.alignment_report.bytes_compared == 0
