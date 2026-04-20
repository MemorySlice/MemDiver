#!/usr/bin/env python3
"""Generate synthetic AES-256 memory dump fixtures for testing.

Creates 30 dumps per tool with different random keys at a fixed offset,
surrounded by identical structural anchors. This allows the consensus matrix
to identify the key region (high variance) and anchors (invariant).

Usage:
    python generate_aes_fixtures.py [--output-dir DIR] [--num-runs N]
"""
import argparse
import os
import random
from pathlib import Path

# Layout constants
DUMP_SIZE = 4096
KEY_OFFSET = 128
KEY_LENGTH = 32
PRE_ANCHOR_OFFSET = 112   # 16 bytes before key
PRE_ANCHOR_LENGTH = 16
POST_ANCHOR_OFFSET = 160  # right after key
POST_ANCHOR_LENGTH = 16
TOOLS = ["memslicer", "lldb", "fridump"]
TIMESTAMP_BASE = "20260410_120001_000001"

# Fixed structural anchors (same across all runs)
# These represent the AES context structure surrounding the key
PRE_ANCHOR = bytes([
    0x01, 0x00, 0x00, 0x00,  # AES context magic / flag
    0x00, 0x01, 0x00, 0x00,  # key length indicator (256)
    0x0E, 0x00, 0x00, 0x00,  # algorithm ID (14 = AES-256-CBC)
    0x10, 0x00, 0x00, 0x00,  # block size (16)
])
POST_ANCHOR = bytes([
    0x00, 0x00, 0x00, 0x00,  # padding counter
    0x01, 0x00, 0x00, 0x00,  # initialized flag
    0x00, 0x00, 0x00, 0x00,  # reserved
    0xFF, 0xFF, 0xFF, 0xFF,  # sentinel
])


# Structural base: identical across all runs (simulates code/static data).
# Generated once per dataset, reused for every dump.
_STRUCTURAL_BASE: bytes | None = None


def _get_structural_base(seed: int = 99) -> bytes:
    """Return a fixed 4096-byte structural base (code + static data)."""
    global _STRUCTURAL_BASE
    if _STRUCTURAL_BASE is None:
        base_rng = random.Random(seed)
        _STRUCTURAL_BASE = base_rng.randbytes(DUMP_SIZE)
    return _STRUCTURAL_BASE


def generate_dump(key: bytes, rng: random.Random) -> bytes:
    """Generate a synthetic memory dump with key at fixed offset.

    Most bytes are identical across all runs (structural base).
    Only the key region (128-159) varies per run.
    Anchors at 112-127 and 160-175 are explicit structural markers.
    """
    data = bytearray(_get_structural_base())
    # Overwrite anchors (redundant but explicit — ensures they're correct)
    data[PRE_ANCHOR_OFFSET:PRE_ANCHOR_OFFSET + PRE_ANCHOR_LENGTH] = PRE_ANCHOR
    data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH] = key
    data[POST_ANCHOR_OFFSET:POST_ANCHOR_OFFSET + POST_ANCHOR_LENGTH] = POST_ANCHOR
    return bytes(data)


def write_keylog(run_dir: Path, key: bytes) -> None:
    """Write a keylog.csv file with the AES key."""
    identifier = "00" * 32  # 32 zero bytes as identifier
    keylog = f"line\nAES256_KEY {identifier} {key.hex()}\n"
    (run_dir / "keylog.csv").write_text(keylog)


def generate_dataset(output_dir: Path, num_runs: int = 30, seed: int = 42) -> dict:
    """Generate the complete AES fixture dataset.

    Returns dict with metadata about generated data.
    """
    rng = random.Random(seed)
    base = output_dir / "AES256" / "aes_key_in_memory"
    keys = []

    for tool in TOOLS:
        tool_dir = base / tool
        for run_idx in range(1, num_runs + 1):
            run_name = f"{tool}_run_256_{run_idx}"
            run_dir = tool_dir / run_name
            run_dir.mkdir(parents=True, exist_ok=True)

            # Each run gets a different random key
            key = rng.randbytes(KEY_LENGTH)
            if tool == TOOLS[0]:  # Track keys from first tool only
                keys.append(key.hex())

            dump_data = generate_dump(key, rng)
            ext = "msl" if tool == "memslicer" else "dump"
            dump_path = run_dir / f"{TIMESTAMP_BASE}_pre_snapshot.{ext}"
            dump_path.write_bytes(dump_data)
            write_keylog(run_dir, key)

    return {
        "output_dir": str(base),
        "num_runs": num_runs,
        "tools": TOOLS,
        "key_offset": KEY_OFFSET,
        "key_length": KEY_LENGTH,
        "pre_anchor_offset": PRE_ANCHOR_OFFSET,
        "post_anchor_offset": POST_ANCHOR_OFFSET,
        "dump_size": DUMP_SIZE,
        "keys": keys,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic AES fixtures")
    parser.add_argument("--output-dir", default="tests/fixtures/dataset",
                        help="Output directory (default: tests/fixtures/dataset)")
    parser.add_argument("--num-runs", type=int, default=30,
                        help="Number of runs per tool (default: 30)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    result = generate_dataset(Path(args.output_dir), args.num_runs, args.seed)
    print(f"Generated {result['num_runs']} runs for {len(result['tools'])} tools")
    print(f"Output: {result['output_dir']}")
    print(f"Key at offset {result['key_offset']}, {result['key_length']} bytes")
    print(f"Anchors at {result['pre_anchor_offset']} and {result['post_anchor_offset']}")


if __name__ == "__main__":
    main()
