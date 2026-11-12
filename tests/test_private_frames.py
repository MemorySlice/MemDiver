"""S4: ``PrivateFrameSource`` and ``frames="private"`` consensus over sibling process views.

Fake process views (``Vol3LayerSource`` over an in-memory adapter) and an injected frame
classifier: no Volatility, no image. The real-data run is in
``test_private_frames_corpus_gate.py``.
"""

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

import memdiver.core.image.private_frames as pf
from memdiver.core.dump_source import RawDumpSource
from memdiver.core.image.adapters import Vma
from memdiver.core.image.private_frames import (
    FRAMES_UNAVAILABLE,
    PRIVATE_FRAMES_DIAGNOSTIC,
    PrivateFrameSource,
    restrict_to_private_frames,
)
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.consensus import (
    ALIGNMENT_MODULE_RELATIVE,
    ALIGNMENT_VIRTUAL_ADDRESS,
    ConsensusVector,
)
from memdiver.engine.consensus_service import build_consensus

P = 0x1000
EXE = "/usr/bin/app"


# -- the wrapper over a bare run table ---------------------------------------------------

class _Runs:
    def __init__(self, runs):
        self._runs = runs
        self.extra = "forwarded"

    def captured_runs(self):
        return tuple(self._runs)


def test_captured_runs_keep_vas_offsets_of_private_sub_runs():
    inner = _Runs([(0x1000, 0x3000, 0), (0x8000, 0x2000, 0x3000)])
    spans = [(0x1000, P, "shared_lineage"), (0x2000, P, "private_dirty"),
             (0x3000, P, "shared_file"), (0x8000, P, "zero"), (0x9000, P, "private_clean")]
    w = PrivateFrameSource(inner, spans)
    assert w.captured_runs() == ((0x2000, P, 0x1000), (0x9000, P, 0x4000))
    assert w.bytes_by_class() == {"shared_lineage": P, "private_dirty": P,
                                  "shared_file": P, "zero": P, "private_clean": P}
    assert (w.captured_bytes(), w.private_bytes()) == (5 * P, 2 * P)
    assert w.extra == "forwarded" and w.wrapped is inner


def test_adjacent_private_classes_merge_and_unclassified_gaps_are_excluded():
    inner = _Runs([(0x10000, 0x5000, 0x100)])
    spans = [(0x10000, P, "private_dirty"), (0x11000, P, "private_file_cow"),
             (0x13800, 0x800, "private_clean"), (0x14000, P, "private_clean")]
    w = PrivateFrameSource(inner, spans)
    # 0x12000-0x13800 has no classified page: never compared
    assert w.captured_runs() == ((0x10000, 2 * P, 0x100), (0x13800, 0x1800, 0x3900))
    assert w.bytes_by_class()["unclassified"] == 0x1800


def test_sub_page_run_boundaries_and_runs_past_the_last_span():
    inner = _Runs([(0x1800, 0x1000, 0), (0x5000, P, P)])
    w = PrivateFrameSource(inner, [(0x1000, P, "private_dirty"), (0x2000, P, "shmem")])
    assert w.captured_runs() == ((0x1800, 0x800, 0),)
    assert w.bytes_by_class() == {"private_dirty": 0x800, "shmem": 0x800,
                                  "unclassified": P}


# -- fake sibling views ------------------------------------------------------------------

#: (logical, offset from base, pages, file_backed, heap)
_PLAN = [("exe", 0x0, 2, True, False), ("heap", 0x100000, 4, False, True)]


class _Process:
    """Bytes depend on (logical VMA, offset); pages listed in ``secret`` differ per member."""

    def __init__(self, base, member, secret_pages):
        self.base, self.member, self.secret_pages = base, member, set(secret_pages)
        self.vma_list = [Vma(base + off, base + off + n * P, EXE if fb else
                             ("[heap]" if heap else ""), "rw-", heap, fb)
                         for _, off, n, fb, heap in _PLAN]

    def vmas(self):
        return list(self.vma_list)

    def runs(self):
        return [LayerRun(v.start, v.end - v.start, RunState.CAPTURED) for v in self.vma_list]

    def read(self, address, length):
        out = bytearray()
        for va in range(address, address + length):
            page = (va - self.base) // P
            out.append((self.member * 31 + va) % 256 if page in self.secret_pages
                       else ((va - self.base) * 7) % 251)
        return bytes(out)

    def describe(self):
        return {"view": "process"}

    def close(self):
        pass


def _view(tmp_path, member, base, *, sha="ab" * 32, pid=None, secret=(0x101,)):
    (tmp_path / "img.lime").write_bytes(b"\x00" * 64)
    desc = ViewDescriptor("img.lime", sha, ViewKind.PROCESS, pid=pid or 100 + member,
                          profile=ProfileRef("p.json"))
    path = desc.write(tmp_path / f"m{member}.mdview")
    adapter = _Process(base, member, secret)
    src = Vol3LayerSource(path, adapter_factory=lambda d, p: adapter)
    src.open()
    return src


def _heap_private_classifier(sources):
    """Exe pages shared_file, heap page 1 private_dirty, the rest of the heap shared_lineage."""
    out = []
    for src in sources:
        exe, heap = src.vmas()
        spans = [(exe.start, exe.end - exe.start, "shared_file")]
        for i in range(4):
            cls = "private_dirty" if i == 1 else "shared_lineage"
            spans.append((heap.start + i * P, P, cls))
        out.append(spans)
    return out


@pytest.fixture
def classifier(monkeypatch):
    monkeypatch.setattr(pf, "classify_view_sources", _heap_private_classifier)


def _build(sources, **kw):
    cm = ConsensusVector()
    cm.build_from_sources(sources, **kw)
    return cm


def test_wrapper_forwards_the_view_api(tmp_path, classifier):
    src = _view(tmp_path, 1, 0x555500000000)
    other = _view(tmp_path, 2, 0x555500000000)
    (w, _), _ = restrict_to_private_frames([src, other])
    assert w.supports_va_alignment and w.va_alignment_by_runs
    assert w.path == src.path and w.format_name == "image_view"
    assert w.va_span_start() == src.va_span_start()
    assert w.layer_runs() == src.layer_runs() and w.vmas() == src.vmas()
    assert w.metadata() == src.metadata() and w.descriptor.pid == 101
    va, n, off = w.captured_runs()[0]
    assert va == 0x555500000000 + 0x101000 and n == P
    assert w.read_range(off, n) == src.read_location(va, n).data
    assert w.read_range_valid(off, 16) == src.read_range_valid(off, 16)
    assert w.va_to_vas_offset(va) == off


def test_frames_all_is_byte_identical_to_the_default(tmp_path, classifier):
    srcs = [_view(tmp_path, m, 0x555500000000) for m in (1, 2, 3)]
    default, explicit = _build(srcs), _build(srcs, frames="all")
    assert np.array_equal(default.variance, explicit.variance)
    assert default.reference_bytes == explicit.reference_bytes
    assert default.alignment_report == explicit.alignment_report
    assert default.msl_layout == explicit.msl_layout


def test_frames_private_forked_compares_only_private_pages(tmp_path, classifier):
    base = 0x555500000000
    srcs = [_view(tmp_path, m, base) for m in (1, 2, 3)]
    full, private = _build(srcs), _build(srcs, frames="private")
    assert full.alignment_report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert private.alignment_report.method == ALIGNMENT_VIRTUAL_ADDRESS
    assert full.alignment_report.bytes_compared == 6 * P
    assert private.alignment_report.bytes_compared == P
    assert [row[2] for row in private.msl_layout] == [[base + 0x101000] * 3]
    assert float(private.variance.max()) > 0  # the per-member page varies
    (note,) = [d for d in private.alignment_report.diagnostics
               if d.code == PRIVATE_FRAMES_DIAGNOSTIC]
    assert note.details["captured_bytes"] == 18 * P
    assert note.details["private_bytes"] == 3 * P
    assert note.details["excluded_bytes"] == 15 * P
    assert note.details["bytes_by_class"] == {"shared_file": 6 * P, "private_dirty": 3 * P,
                                              "shared_lineage": 9 * P}
    assert [s["pid"] for s in note.details["per_source"]] == [101, 102, 103]
    assert all(d.code != PRIVATE_FRAMES_DIAGNOSTIC for d in full.alignment_report.diagnostics)


def test_frames_private_independent_uses_module_relative(tmp_path, classifier):
    srcs = [_view(tmp_path, 1, 0x555500000000), _view(tmp_path, 2, 0x561234560000)]
    cm = _build(srcs, frames="private")
    assert cm.alignment_report.method == ALIGNMENT_MODULE_RELATIVE
    assert cm.alignment_report.bytes_compared == P
    assert [row[2] for row in cm.msl_layout] == [[0x555500101000, 0x561234661000]]


def test_frames_private_refuses_non_view_sources(tmp_path):
    raws = []
    for i in (1, 2):
        p = tmp_path / f"d{i}.dump"
        p.write_bytes(bytes(64))
        raws.append(RawDumpSource(p))
    with pytest.raises(CapabilityError) as err:
        _build(raws, frames="private")
    assert err.value.code == FRAMES_UNAVAILABLE


def test_frames_private_refuses_views_of_different_images(tmp_path, classifier):
    srcs = [_view(tmp_path, 1, 0x555500000000),
            _view(tmp_path, 2, 0x555500000000, sha="cd" * 32)]
    with pytest.raises(CapabilityError) as err:
        _build(srcs, frames="private")
    assert err.value.code == FRAMES_UNAVAILABLE and "SAME memory image" in str(err.value)


def test_frames_private_refuses_the_same_pid_twice(tmp_path, classifier):
    srcs = [_view(tmp_path, 1, 0x555500000000, pid=7),
            _view(tmp_path, 2, 0x555500000000, pid=7)]
    with pytest.raises(CapabilityError) as err:
        _build(srcs, frames="private")
    assert err.value.code == FRAMES_UNAVAILABLE


def test_unknown_frames_value_is_refused_before_opening(tmp_path):
    with pytest.raises(CapabilityError) as err:
        build_consensus([tmp_path / "missing1", tmp_path / "missing2"], frames="shared")
    assert err.value.code == "consensus.unknown_frames"


def test_build_consensus_threads_frames(tmp_path, monkeypatch, classifier):
    import memdiver.core.image.sources as sources_mod
    adapters = {}

    def factory(desc, path):
        return adapters[desc.pid]

    monkeypatch.setattr(sources_mod, "_default_adapter_factory", factory)
    paths = []
    for m in (1, 2):
        _view(tmp_path, m, 0x555500000000).close()
        adapters[100 + m] = _Process(0x555500000000, m, (0x101,))
        paths.append(tmp_path / f"m{m}.mdview")
    default = build_consensus(paths, allocator="off")
    explicit = build_consensus(paths, allocator="off", frames="all")
    private = build_consensus(paths, allocator="off", frames="private")
    assert np.array_equal(default.variance, explicit.variance)
    assert default.alignment_report == explicit.alignment_report
    assert private.alignment_report.bytes_compared == P


def test_default_classifier_maps_classified_pages_to_spans(monkeypatch):
    pages = [SimpleNamespace(member=5, va=0x1000, length=P, share_class="private_dirty"),
             SimpleNamespace(member=6, va=0x1000, length=P, share_class="shared_lineage")]
    result = SimpleNamespace(classification=SimpleNamespace(pages=pages),
                             same_address_space={})
    seen = {}

    def fake_classify(ctx, pids):
        seen["pids"] = pids
        return result

    import memdiver.core.image.context as ctx_mod
    import memdiver.core.image.page_sharing as ps
    monkeypatch.setattr(ctx_mod, "image_context_for", lambda d, p: "ctx")
    monkeypatch.setattr(ps, "classify_processes", fake_classify)
    srcs = [SimpleNamespace(descriptor=SimpleNamespace(pid=pid), path="/x.mdview")
            for pid in (6, 5)]
    assert pf.classify_view_sources(srcs) == [[(0x1000, P, "shared_lineage")],
                                              [(0x1000, P, "private_dirty")]]
    assert seen["pids"] == [6, 5]
    result.same_address_space = {6: 5}
    with pytest.raises(CapabilityError) as err:
        pf.classify_view_sources(srcs)
    assert err.value.code == FRAMES_UNAVAILABLE
