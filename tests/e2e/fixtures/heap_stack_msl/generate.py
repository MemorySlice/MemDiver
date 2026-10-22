#!/usr/bin/env python3
"""Generate the committed heap + stack MSL fixture for the e2e import specs.

A live-capture ``.msl`` with exactly two captured MEMORY_REGIONs -- a heap
(2 pages at 0x10000000) and a thread stack (1 page at 0x7FFF0000) -- plus a
VAS_MAP listing both. Unticking "stack" in the wizard's Regions step therefore
excludes exactly one region (4 KiB), which the materialize spec asserts on.
The dump UUID is fixed so the spec can check the materialized copy keeps it.

Run from the repo root (or anywhere):

    python tests/e2e/fixtures/heap_stack_msl/generate.py
"""

import random
import sys
from pathlib import Path
from uuid import UUID

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/heap_stack_msl -> repo root
sys.path.insert(0, str(REPO_ROOT.parent))

import memdiver.msl.writer as msl_writer  # noqa: E402
from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.types import MslVasEntry  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

OUTPUT = HERE / "sample.msl"
DUMP_UUID = UUID("5eedc0de-0000-4000-8000-00000000beef")
PAGE = 4096
HEAP_BASE, HEAP_PAGES = 0x10000000, 2
STACK_BASE, STACK_PAGES = 0x7FFF0000, 1
RW = int(Protection.READ | Protection.WRITE)
TIMESTAMP_NS = 1_700_000_000_000_000_000
_UUID_SEED = 0x5EED


def _seeded_uuid4_factory(seed: int):
    """Deterministic stand-in for ``uuid4`` so block UUIDs (and therefore the
    PrevHash chain and EoC file hash) are byte-stable across regenerations."""
    rng = random.Random(seed)
    return lambda: UUID(int=rng.getrandbits(128), version=4)


def main() -> None:
    msl_writer.uuid4 = _seeded_uuid4_factory(_UUID_SEED)
    w = MslWriter(OUTPUT, pid=4242, imported=False, dump_uuid=DUMP_UUID,
                  timestamp_ns=TIMESTAMP_NS)
    w.add_process_identity(ppid=1, exe_path="/usr/bin/app", cmd_line="app")
    w.add_memory_region(HEAP_BASE, bytes(range(256)) * (16 * HEAP_PAGES),
                        protection=RW, region_type=RegionType.HEAP)
    w.add_memory_region(STACK_BASE, b"\x5a" * (PAGE * STACK_PAGES),
                        protection=RW, region_type=RegionType.STACK)
    w.add_vas_map([
        MslVasEntry(HEAP_BASE, PAGE * HEAP_PAGES, RW, RegionType.HEAP, ""),
        MslVasEntry(STACK_BASE, PAGE * STACK_PAGES, RW, RegionType.STACK,
                    "[stack]"),
    ])
    w.add_end_of_capture(acq_end_ns=TIMESTAMP_NS + 1_000_000_000)
    w.write()
    print(f"Wrote {OUTPUT.stat().st_size} bytes to {OUTPUT}")


if __name__ == "__main__":
    main()
