"""End-to-end heap analysis of ``.msl`` dumps built with :class:`MslWriter`.

MSL is MemDiver's primary dump format, so the heap layer must see the
VAS_MAP mapping names (``[heap]``, ``[anon:scudo:primary]``, module paths)
even when the file is IMPORTED without a ``region_names=1`` provenance note
(the writer default), where region classification ignores them.
"""

import pytest

from memdiver.core.dump_source import open_dump
from memdiver.heap.analyze import analyze_heap
from memdiver.heap.model import AllocatorKind
from memdiver.heap.platform import memory_map_of, module_paths
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import ModuleEntrySpec, MslWriter
from tests.fixtures import synth_heap as sh

LIBC_VA = 0x7F00_0000_0000
LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
_RW, _RX = 0x03, 0x05


def _write_msl(path, heap, os_type, module_path, *, imported=True):
    """MSL holding every region of *heap* plus a VAS-only *module_path*."""
    writer = MslWriter(path, os_type=os_type, arch_type=ArchType.X86_64,
                       imported=imported)
    vas = []
    for idx, (va, size, name) in enumerate(heap.regions):
        writer.add_memory_region(va, heap.region_bytes(idx), protection=_RW)
        vas.append(MslVasEntry(va, size, _RW, 0, name))
    writer.add_module_list_index([ModuleEntrySpec(LIBC_VA, 0x1000, module_path)])
    vas.append(MslVasEntry(LIBC_VA, 0x1000, _RX, 0, module_path))
    writer.add_vas_map(vas)
    writer.write()
    return path


def _chunk_triples(chunks):
    return [(c.va, c.size, c.state) for c in chunks]


@pytest.mark.parametrize("imported", [True, False])
def test_memory_map_carries_vas_names(tmp_path, imported):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "h.msl", heap, OSType.LINUX, LIBC_PATH,
                      imported=imported)
    with open_dump(path) as src:
        regions = memory_map_of(src)
        assert [(r.va, r.name, r.captured) for r in regions] == [
            (heap.base_va, "[heap]", True)]
        assert LIBC_PATH in module_paths(src)


def test_split_region_blocks_all_named(tmp_path):
    heap = sh.glibc_heap(region_size=4 * sh.PAGE)
    path = tmp_path / "h.msl"
    writer = MslWriter(path, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       region_block_cap=sh.PAGE)
    writer.add_memory_region(heap.base_va, heap.data, protection=_RW)
    writer.add_vas_map([MslVasEntry(heap.base_va, len(heap.data), _RW, 0,
                                    "[heap]")])
    writer.write()
    with open_dump(path) as src:
        names = {r.name for r in memory_map_of(src)}
    assert names == {"[heap]"}


def test_analyze_glibc_heap_msl(tmp_path):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "glibc.msl", heap, OSType.LINUX, LIBC_PATH)
    with open_dump(path) as src:
        layout = analyze_heap(src)
    assert layout.allocator is AllocatorKind.PTMALLOC2
    assert _chunk_triples(layout.chunks) == _chunk_triples(heap.chunks)


def test_analyze_scudo_primary_msl(tmp_path):
    heap = sh.scudo_primary()
    path = _write_msl(tmp_path / "scudo.msl", heap, OSType.ANDROID,
                      "/apex/com.android.runtime/lib64/bionic/libc.so")
    with open_dump(path) as src:
        layout = analyze_heap(src)
    assert layout.allocator is AllocatorKind.SCUDO
    assert _chunk_triples(layout.chunks) == _chunk_triples(heap.chunks)
