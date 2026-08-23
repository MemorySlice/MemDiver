"""VA-coordinate access on ConsensusVector (MSL overlay + heatmap basis).

These exercise the slab<->virtual-address mapping directly with a hand-built
layout, so they need no real .msl fixtures. Two aligned pages, two dumps at
different ASLR bases; the same slab indices back both dumps' VAs.
"""

import numpy as np

from memdiver.engine.consensus import ConsensusVector
from memdiver.core.variance import ByteClass


def _vector():
    cm = ConsensusVector()
    # slab: [inv, inv, struct, key | ptr, ptr, inv, inv]
    cm._classifications = np.array([0, 0, 1, 3, 2, 2, 0, 0], dtype=np.uint8)
    # (slab_offset, page_size, [va_dump0, va_dump1]) — dump1 is ASLR-shifted.
    cm.msl_layout = [
        (0, 4, [0x1000, 0x5000]),
        (4, 4, [0x2000, 0x6000]),
    ]
    cm.dump_paths = ["/run/a.msl", "/run/b.msl"]
    cm._va_index_cache = {}
    return cm


def test_dump_index_for_path():
    cm = _vector()
    assert cm.dump_index_for_path("/run/a.msl") == 0
    assert cm.dump_index_for_path("/run/b.msl") == 1
    assert cm.dump_index_for_path("/run/missing.msl") == -1


def test_class_window_exact_page_dump0():
    cm = _vector()
    assert cm.class_window_va(0, 0x1000, 4) == [0, 0, 1, 3]
    assert cm.class_window_va(0, 0x2000, 4) == [2, 2, 0, 0]


def test_class_window_marks_gaps():
    cm = _vector()
    # 0x1000..0x1003 captured, 0x1004..0x1007 is a VA gap between pages.
    assert cm.class_window_va(0, 0x1000, 8) == [0, 0, 1, 3, -1, -1, -1, -1]


def test_class_window_partial_start():
    cm = _vector()
    # Start mid-page: 0x1002,0x1003 then gap.
    assert cm.class_window_va(0, 0x1002, 4) == [1, 3, -1, -1]


def test_second_dump_uses_its_own_va_same_classes():
    cm = _vector()
    # Dump 1 sits at a different base but maps to the SAME slab classes.
    assert cm.class_window_va(1, 0x5000, 4) == [0, 0, 1, 3]
    assert cm.class_window_va(1, 0x6000, 4) == [2, 2, 0, 0]


def test_class_window_all_gap_outside_span():
    cm = _vector()
    assert cm.class_window_va(0, 0x9000, 4) == [-1, -1, -1, -1]


def test_no_layout_returns_all_gap():
    cm = ConsensusVector()  # raw build: msl_layout is None
    assert cm.msl_layout is None
    assert cm.class_window_va(0, 0, 4) == [-1, -1, -1, -1]


def test_va_overview_span_and_fractions():
    cm = _vector()
    ov = cm.va_overview(0, bins=256)
    assert ov["va_start"] == 0x1000
    assert ov["va_end"] == 0x2004
    # Page 0 (classes 0,0,1,3): half changing, a quarter high, peak level KEY.
    assert ov["changing"][0] == 0.5
    assert ov["high"][0] == 0.25
    assert ov["level"][0] == int(ByteClass.KEY_CANDIDATE)
    # Bins with no captured pages read as zero change.
    assert min(ov["changing"]) == 0.0
