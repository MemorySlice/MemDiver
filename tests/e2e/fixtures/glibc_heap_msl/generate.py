#!/usr/bin/env python3
"""Generate the committed glibc-heap MSL fixture for the heap-mode e2e spec.

A live-capture ``.msl`` whose single captured MEMORY_REGION is the synthetic
glibc ptmalloc2 ``[heap]`` from ``tests/fixtures/synth_heap.glibc_heap()``
(tcache_perthread_struct, three in-use chunks, three tcache'd chunks in two
bins, then the top chunk), plus a VAS_MAP naming it ``[heap]`` and a
module list carrying ``libc.so.6`` -- the shape ``tests/test_heap_msl.py``
proves ``analyze_heap`` resolves to ptmalloc2 with every chunk recovered.

The expected-chunk oracle is written next to the MSL as ``expected.json`` so
the spec asserts against the same numbers the Python builder produced.
Block UUIDs and the dump UUID are seeded, so regeneration is byte-stable.

Run from the repo root (or anywhere):

    python tests/e2e/fixtures/glibc_heap_msl/generate.py
"""

import json
import random
import sys
from pathlib import Path
from uuid import UUID

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/glibc_heap_msl -> repo root
sys.path.insert(0, str(REPO_ROOT.parent))
sys.path.insert(0, str(REPO_ROOT))

import memdiver.msl.writer as msl_writer  # noqa: E402
from memdiver.msl.enums import ArchType, OSType  # noqa: E402
from memdiver.msl.types import MslVasEntry  # noqa: E402
from memdiver.msl.writer import ModuleEntrySpec, MslWriter  # noqa: E402
from tests.fixtures import synth_heap as sh  # noqa: E402

OUTPUT = HERE / "sample.msl"
EXPECTED = HERE / "expected.json"
DUMP_UUID = UUID("5eedc0de-0000-4000-8000-0000000ea900")
LIBC_VA = 0x7F00_0000_0000
LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
RW, RX = 0x03, 0x05
TIMESTAMP_NS = 1_700_000_000_000_000_000
_UUID_SEED = 0x6EA9


def _seeded_uuid4_factory(seed: int):
    """Deterministic stand-in for ``uuid4`` (byte-stable regenerations)."""
    rng = random.Random(seed)
    return lambda: UUID(int=rng.getrandbits(128), version=4)


def _write_msl(heap: sh.SynthHeap) -> None:
    msl_writer.uuid4 = _seeded_uuid4_factory(_UUID_SEED)
    writer = MslWriter(OUTPUT, pid=4243, os_type=OSType.LINUX,
                       arch_type=ArchType.X86_64, imported=False,
                       dump_uuid=DUMP_UUID, timestamp_ns=TIMESTAMP_NS)
    writer.add_process_identity(ppid=1, exe_path="/usr/bin/app", cmd_line="app")
    vas = []
    for idx, (va, size, name) in enumerate(heap.regions):
        writer.add_memory_region(va, heap.region_bytes(idx), protection=RW)
        vas.append(MslVasEntry(va, size, RW, 0, name))
    writer.add_module_list_index([ModuleEntrySpec(LIBC_VA, 0x1000, LIBC_PATH)])
    vas.append(MslVasEntry(LIBC_VA, 0x1000, RX, 0, LIBC_PATH))
    writer.add_vas_map(vas)
    writer.add_end_of_capture(acq_end_ns=TIMESTAMP_NS + 1_000_000_000)
    writer.write()


def _expected(heap: sh.SynthHeap) -> dict:
    tcache_bins = sorted({c.bin for c in heap.chunks
                          if c.bin and c.bin.startswith("tcache[")})
    return {
        "allocator": heap.allocator,
        "base_va": heap.base_va,
        "chunk_count": len(heap.chunks),
        "tcache_bins": tcache_bins,
        "chunks": [{"va": c.va, "size": c.size, "state": c.state.value,
                    "header_len": c.header_len, "bin": c.bin}
                   for c in heap.chunks],
    }


def main() -> None:
    heap = sh.glibc_heap()
    _write_msl(heap)
    EXPECTED.write_text(json.dumps(_expected(heap), indent=2) + "\n")
    print(f"Wrote {OUTPUT.stat().st_size} bytes to {OUTPUT}")
    print(f"Wrote expected-chunk oracle to {EXPECTED}")


if __name__ == "__main__":
    main()
