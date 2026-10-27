"""heap.* over image views: a PHYSICAL ``.mdview`` is refused up front.

A physical view reports a "va" map, but its addresses are physical frames; the
allocator walkers follow virtual pointers, so heap analysis over it would read
unrelated pages. Process and kernel views carry real virtual addresses.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest

from memdiver.app import tools_heap as th
from memdiver.app.session import ToolSession
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import (PagingSpec, ProfileRef,
                                                 ViewDescriptor, ViewKind)
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.heap.analyze import clear_heap_cache

SHA = "cd" * 32
RUNS = [LayerRun(0x10000, 0x2000, RunState.CAPTURED)]


class _Adapter:
    def runs(self):
        return RUNS

    def read(self, address, length):
        return bytes(length)

    def describe(self):
        return {"layer": "fake"}

    def close(self):
        pass


def _descriptor(kind: ViewKind) -> ViewDescriptor:
    if kind is ViewKind.PROCESS:
        return ViewDescriptor("img.bin", SHA, kind, pid=7, profile=ProfileRef("p.json"))
    if kind is ViewKind.KERNEL:
        return ViewDescriptor("img.bin", SHA, kind, profile=ProfileRef("p.json"))
    return ViewDescriptor("img.bin", SHA, kind)


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


@pytest.fixture
def view_of(tmp_path, monkeypatch):
    """``view_of(kind)`` -> the ``.mdview`` path; tools_heap opens it over a fake layer."""

    def make(kind: ViewKind) -> str:
        (tmp_path / "img.bin").write_bytes(b"\xee" * 0x20000)
        path = _descriptor(kind).write(tmp_path / f"{kind.value}.mdview")

        @contextmanager
        def fake_open(dump_path, _key_material):
            source = Vol3LayerSource(path, adapter_factory=lambda d, p: _Adapter())
            source.open()
            try:
                yield source
            finally:
                source.close()

        monkeypatch.setattr(th, "open_dump_source", fake_open)
        return str(path)

    return make


PRODUCERS = [
    (th.heap_detect_result, {}),
    (th.heap_summary_result, {}),
    (th.heap_chunks_result, {}),
    (th.heap_chunk_at_result, {"va": 0x10000}),
    (th.heap_free_lists_result, {}),
    (th.heap_roles_result, {}),
]


@pytest.mark.parametrize("producer, kwargs", PRODUCERS,
                         ids=[p.__name__ for p, _ in PRODUCERS])
def test_every_heap_producer_refuses_a_physical_view(view_of, producer, kwargs):
    path = view_of(ViewKind.PHYSICAL)
    with pytest.raises(CapabilityError) as refused:
        producer(ToolSession(), path, **kwargs)
    assert refused.value.code == "heap.physical_view_unsupported"
    assert refused.value.category is ErrorCategory.UNSUPPORTED
    assert refused.value.details == {"view_kind": "physical"}
    assert "process view" in str(refused.value)


def test_explicit_base_va_does_not_bypass_the_physical_guard(view_of):
    path = view_of(ViewKind.PHYSICAL)
    with pytest.raises(CapabilityError) as refused:
        th.heap_detect_result(ToolSession(), path, base_va=0x10000)
    assert refused.value.code == "heap.physical_view_unsupported"


@pytest.mark.parametrize("kind", [ViewKind.PROCESS, ViewKind.KERNEL])
def test_virtual_views_are_analysed(view_of, kind):
    result = th.heap_detect_result(ToolSession(), view_of(kind))
    assert result.payload["format"] == "image_view"


def test_non_image_sources_are_not_affected():
    th._refuse_physical_view(object())  # no descriptor: a plain dump passes


def test_kernel_view_with_paging_only_is_allowed():
    descriptor = ViewDescriptor("img.bin", SHA, ViewKind.KERNEL,
                                paging=PagingSpec(pgd_phys=0x1000, arch="x86_64"))
    th._refuse_physical_view(type("S", (), {"descriptor": descriptor})())
