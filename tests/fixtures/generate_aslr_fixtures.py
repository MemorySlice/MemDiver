#!/usr/bin/env python3
"""ASLR-aware fixture generator producing raw dumps and proper MSL files.

Each run places an AES-256 struct in a heap region at a random ASLR base
address. Three regions (code, stack, heap) always have the SAME sizes but
DIFFERENT base addresses. This means:

- RAW dumps: regions sorted by VA → struct offset in file VARIES because
  the heap's position among code/stack changes per run.
- MSL files: region base_addr metadata enables ASLR-normalized alignment
  by matching anonymous region keys (type+size+ordinal).

Usage: python generate_aslr_fixtures.py [--output-dir DIR] [--num-runs N]
"""
import argparse
import json
import random
import struct as pystruct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from msl.writer import MslWriter
from msl.enums import OSType, ArchType

PAGE_SIZE = 4096
STRUCT_SIZE = 336
STRUCT_OFFSET_IN_HEAP = 0x100
TIMESTAMP_BASE = "20260410_120001_000001"

# Fixed region sizes (same across all runs for MSL alignment)
CODE_SIZE = PAGE_SIZE       # 4096
STACK_SIZE = PAGE_SIZE      # 4096
HEAP_SIZE = 2 * PAGE_SIZE   # 8192

# Deterministic fills for code and stack (identical across runs)
_CODE_FILL = random.Random(77).randbytes(CODE_SIZE)
_STACK_FILL = random.Random(88).randbytes(STACK_SIZE)
_HEAP_FILL = random.Random(99).randbytes(HEAP_SIZE)


def build_aes_struct(key: bytes, iv: bytes) -> bytes:
    """Build a 336-byte AES context struct (little-endian)."""
    header = pystruct.pack("<IIII", 0x41455332, 256, 14, 16)
    trailer = pystruct.pack("<IIII", 14, 1, 0, 0xDEADBEEF)
    round_keys = bytes((k ^ i) & 0xFF for i, k in
                       enumerate(key * 8))[:240]
    round_keys += b"\x00" * 16
    return header + key + iv + trailer + round_keys


def generate_run(rng: random.Random):
    """Generate one run with ASLR-randomized base addresses.

    Always 3 regions (code, stack, heap) of fixed sizes at random VAs.
    The heap contains the AES struct at STRUCT_OFFSET_IN_HEAP.
    """
    key = rng.randbytes(32)
    iv = rng.randbytes(16)
    aes_struct = build_aes_struct(key, iv)

    # Random page-aligned base addresses (all different)
    bases = set()
    while len(bases) < 3:
        bases.add(rng.randint(0x100, 0xFFFFF) * PAGE_SIZE)
    code_base, stack_base, heap_base = sorted(bases)
    # Shuffle assignment so heap isn't always in the same position
    assignment = list(bases)
    rng.shuffle(assignment)
    code_base, stack_base, heap_base = assignment

    # Build heap with struct embedded
    heap_data = bytearray(_HEAP_FILL)
    heap_data[STRUCT_OFFSET_IN_HEAP:STRUCT_OFFSET_IN_HEAP + STRUCT_SIZE] = \
        aes_struct

    # Regions: (base_addr, data, label)
    regions = [
        (code_base, _CODE_FILL, "code"),
        (stack_base, _STACK_FILL, "stack"),
        (heap_base, bytes(heap_data), "heap"),
    ]
    # Sort by base address (how dumpers capture regions)
    regions.sort(key=lambda r: r[0])

    # Compute struct's byte offset in concatenated raw dump
    raw_offset = 0
    for base, data, label in regions:
        if label == "heap":
            raw_offset += STRUCT_OFFSET_IN_HEAP
            break
        raw_offset += len(data)

    return regions, key, iv, raw_offset, heap_base


def write_raw_run(run_dir: Path, regions, key: bytes):
    """Write concatenated raw dump."""
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_data = b"".join(data for _, data, _ in regions)
    (run_dir / f"{TIMESTAMP_BASE}_pre_snapshot.dump").write_bytes(raw_data)
    _write_keylog(run_dir, key)


def write_msl_run(run_dir: Path, regions, key: bytes, pid: int = 1234):
    """Write MSL file with base_addr per region."""
    run_dir.mkdir(parents=True, exist_ok=True)
    msl_path = run_dir / f"{TIMESTAMP_BASE}_pre_snapshot.msl"
    writer = MslWriter(msl_path, pid=pid,
                       os_type=OSType.MACOS, arch_type=ArchType.X86_64,
                       imported=False)
    for base, data, _label in regions:
        writer.add_memory_region(base_addr=base, data=data,
                                 page_size_log2=12)
    writer.add_end_of_capture()
    writer.write()
    _write_keylog(run_dir, key)


def _write_keylog(run_dir: Path, key: bytes):
    keylog = f"line\nAES256_KEY {'00' * 32} {key.hex()}\n"
    (run_dir / "keylog.csv").write_text(keylog)


def generate_dataset(output_dir: Path, num_runs: int = 30,
                     seed: int = 42) -> dict:
    """Generate ASLR fixture dataset with raw and MSL variants."""
    rng = random.Random(seed)
    output_dir = Path(output_dir)
    metadata = {"seed": seed, "num_runs": num_runs, "runs": []}

    for run_idx in range(1, num_runs + 1):
        regions, key, iv, raw_offset, heap_base = generate_run(rng)
        raw_dir = output_dir / "raw" / f"raw_run_256_{run_idx}"
        msl_dir = output_dir / "msl" / f"msl_run_256_{run_idx}"
        write_raw_run(raw_dir, regions, key)
        write_msl_run(msl_dir, regions, key)

        metadata["runs"].append({
            "run": run_idx,
            "key_hex": key.hex(),
            "heap_base": hex(heap_base),
            "struct_offset_in_heap": STRUCT_OFFSET_IN_HEAP,
            "struct_offset_in_raw": raw_offset,
            "region_order": [label for _, _, label in regions],
        })

    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return metadata


def main():
    parser = argparse.ArgumentParser(
        description="Generate ASLR-aware raw + MSL fixtures")
    parser.add_argument("--output-dir",
                        default="tests/fixtures/dataset/aslr")
    parser.add_argument("--num-runs", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    meta = generate_dataset(Path(args.output_dir), args.num_runs, args.seed)
    offsets = [r["struct_offset_in_raw"] for r in meta["runs"]]
    orders = [tuple(r["region_order"]) for r in meta["runs"]]
    print(f"Generated {meta['num_runs']} runs (raw + MSL)")
    print(f"Unique raw offsets: {len(set(offsets))}/{len(offsets)}")
    print(f"Unique region orders: {len(set(orders))}/{len(orders)}")
    for off in sorted(set(offsets)):
        n = offsets.count(off)
        order = next(r["region_order"] for r in meta["runs"]
                     if r["struct_offset_in_raw"] == off)
        print(f"  offset=0x{off:04x} ({n}x) order={order}")


if __name__ == "__main__":
    main()
