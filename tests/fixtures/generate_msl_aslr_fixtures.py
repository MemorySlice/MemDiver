"""Synthetic MSL fixture generator for ASLR-shifted run pairs.

Builds two MSL files with identical secrets at the same page offset but
different base addresses (simulating ASLR).  Uses raw struct packing
(not MslWriter) to control page state bitmaps precisely.
"""

import random
import struct
from pathlib import Path

from tests.fixtures.generate_fixtures import _xor_secret
from tests.fixtures.generate_msl_fixtures import (
    BLOCK_HEADER_SIZE,
    FILE_HEADER_SIZE,
    PAGE_SIZE,
    PAGE_SIZE_LOG2,
    _build_block,
    _build_end_of_capture,
    _build_file_header,
    _build_module_entry,
    _build_process_identity,
    _pad8,
)

_RNG = random.Random(99)

SECRET_BASE = bytes([0xAA] * 32)
SECRET_OFFSET_IN_PAGE = 64
MODULE_BASE_RUN1 = 0x00400000
MODULE_BASE_RUN2 = 0x00500000
HEAP_BASE_RUN1 = 0x7FFF00000000
HEAP_BASE_RUN2 = 0x7FFF10000000

SECRET_VALUES_BY_RUN = {
    1: _xor_secret(SECRET_BASE, 1),
    2: _xor_secret(SECRET_BASE, 2),
}


def _det_uuid() -> bytes:
    """Generate a deterministic 16-byte UUID from module-local RNG."""
    return bytes(_RNG.getrandbits(8) for _ in range(16))


def _build_memory_region_mixed(base_addr, num_pages, page_state_map,
                               page_data):
    """Build Memory Region block with a caller-supplied page state bitmap.

    Unlike the standard ``_build_memory_region`` (which hardcodes all
    pages as CAPTURED), this variant accepts arbitrary page state bytes
    so tests can model partial captures (e.g. page 0 CAPTURED, page 1
    FAILED).
    """
    region_size = num_pages * PAGE_SIZE
    bitmap_padded = _pad8(((num_pages * 2) + 7) // 8)
    psm = page_state_map.ljust(bitmap_padded, b"\x00")
    payload = struct.pack(
        "<QQBBB5xQ",
        base_addr, region_size,
        0x07, 0x01, PAGE_SIZE_LOG2, 0,  # RWX, HEAP, log2, timestamp
    )
    payload += psm
    if page_data is not None:
        payload += page_data
    return _build_block(0x0001, payload)


def _build_single_run(run_num, module_base, heap_base, pad_byte):
    """Assemble one complete MSL blob for a single ASLR-shifted run."""
    global _RNG
    # Deterministic per-run UUID stream (seed 99 + run_num)
    _RNG = random.Random(99 + run_num)

    timestamp_ns = 1_700_000_000_000_000_000 + run_num * 1_000_000
    dump_uuid = _det_uuid()
    blob = _build_file_header(dump_uuid, timestamp_ns, pid=1234)

    # Process Identity
    proc_block, _ = _build_process_identity()
    blob += proc_block

    # Module Entry — libssl.so at ASLR-shifted base
    mod_block, _ = _build_module_entry(
        base_addr=module_base, module_size=0x100000,
        path="/usr/lib/libssl.so", version="1.1.1",
    )
    blob += mod_block

    # Memory Region — 2 pages, page 0 CAPTURED, page 1 FAILED
    # 2 bits per page: 00=CAPTURED, 01=FAILED → byte = 0b0001_0000 = 0x10
    page_state_map = b"\x10"
    secret = SECRET_VALUES_BY_RUN[run_num]
    page_data = bytearray([pad_byte] * PAGE_SIZE)
    page_data[SECRET_OFFSET_IN_PAGE:SECRET_OFFSET_IN_PAGE + len(secret)] = secret
    region_block, _ = _build_memory_region_mixed(
        heap_base, 2, page_state_map, bytes(page_data),
    )
    blob += region_block

    # End of Capture
    eoc_block, _ = _build_end_of_capture(timestamp_ns + 1_000_000_000)
    blob += eoc_block

    return blob


def generate_aslr_msl_pair():
    """Return ``(run1_bytes, run2_bytes)`` — two ASLR-shifted MSL blobs."""
    run1 = _build_single_run(1, MODULE_BASE_RUN1, HEAP_BASE_RUN1, 0x00)
    run2 = _build_single_run(2, MODULE_BASE_RUN2, HEAP_BASE_RUN2, 0xFE)
    return run1, run2


def write_aslr_msl_fixtures(root):
    """Write ``root/run_1.msl`` and ``root/run_2.msl``."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    run1, run2 = generate_aslr_msl_pair()
    (root / "run_1.msl").write_bytes(run1)
    (root / "run_2.msl").write_bytes(run2)
    return root


if __name__ == "__main__":
    out = write_aslr_msl_fixtures(
        Path(__file__).parent / "dataset" / "msl" / "aslr",
    )
    print(f"ASLR MSL fixtures written to: {out}")
