#!/usr/bin/env python3
"""Generate realistic memory dump fixtures with various noise types.

Creates dumps that mimic real process memory with:
- AES-256 key at known offset (TRUE POSITIVE: high entropy + high variance)
- SHA-256 hashes embedded in binary (FP for entropy: high entropy, invariant)
- Compressed blocks (FP for entropy: high entropy, invariant)
- Heap metadata / counters (FP for variance: low entropy, high variance)
- Pointers (FP for variance: medium entropy, high variance)
- Random session IDs (FP for both: high entropy, high variance)

This shows why combining entropy + variance dramatically reduces false positives.

Usage: python generate_realistic_fixtures.py [--output-dir DIR] [--num-runs N]
"""
import argparse
import hashlib
import random
import struct
import sys
import zlib
from pathlib import Path

DUMP_SIZE = 65536  # 64KB — realistic for a single heap region
KEY_OFFSET = 0x1000  # AES key at 4096
KEY_LENGTH = 32
NUM_TOOLS = 3
TOOL_NAMES = ["memslicer", "lldb", "fridump"]
TIMESTAMP_BASE = "20260410_120001_000001"

# Decryption verification constants
VERIFICATION_PLAINTEXT = b"AES256_MEMDIVER_VERIFICATION_OK!"  # exactly 32 bytes
VERIFICATION_IV = bytes(range(16))  # fixed IV for reproducibility


def _build_structural_base(seed: int = 42) -> bytearray:
    """Build the invariant structural base (same across all runs).

    Contains realistic memory patterns:
    - Code-like sequences (low entropy, invariant)
    - Embedded SHA-256 hashes (high entropy, invariant)
    - Compressed data blocks (high entropy, invariant)
    - Struct padding / alignment bytes (low entropy, invariant)
    """
    rng = random.Random(seed)
    data = bytearray(DUMP_SIZE)

    # Region 0x000-0x400: ELF/PE-like header (low entropy, structural)
    for i in range(0, 0x400, 4):
        data[i:i + 4] = b"\x00\x00\x00\x00"  # Mostly zeros like real headers
    data[0:4] = b"\x7fELF"  # ELF magic
    data[0x10:0x14] = struct.pack("<I", 0x00000002)  # e_type

    # Region 0x400-0x800: Code section (medium entropy, structural)
    code_patterns = [
        b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
        b"\x48\x83\xec\x20",  # sub rsp, 0x20
        b"\x89\x7d\xfc",      # mov [rbp-4], edi
        b"\x48\x8b\x45\xf8",  # mov rax, [rbp-8]
        b"\xc3\x90\x90\x90",  # ret; nop; nop; nop
    ]
    pos = 0x400
    while pos < 0x800:
        pat = code_patterns[rng.randint(0, len(code_patterns) - 1)]
        end = min(pos + len(pat), 0x800)
        data[pos:end] = pat[:end - pos]
        pos = end

    # Region 0x800-0xA00: Embedded SHA-256 hashes (HIGH entropy, invariant)
    # These are FPs for entropy-only: look like key material but are static
    for i in range(8):
        h = hashlib.sha256(f"certificate_{i}".encode()).digest()
        off = 0x800 + i * 40  # 32B hash + 8B struct padding
        data[off:off + 32] = h
        data[off + 32:off + 40] = struct.pack("<Q", i)  # index

    # Region 0xA00-0xC00: Compressed data (HIGH entropy, invariant)
    plaintext = b"This is a repeated configuration block. " * 20
    compressed = zlib.compress(plaintext, 9)
    comp_len = min(len(compressed), 0x200)
    data[0xA00:0xA00 + comp_len] = compressed[:comp_len]

    # Region 0xC00-0x1000: Struct padding, vtable pointers (low entropy)
    for i in range(0xC00, 0x1000, 8):
        data[i:i + 8] = struct.pack("<Q", 0x00007FFF00000000 + i)

    # Region 0x1000-0x1010: AES context pre-anchor (invariant)
    data[0xFF0:0x1000] = struct.pack("<IIII",
                                      0x41455332, 256, 14, 16)

    # Region 0x1020-0x1030: AES context post-anchor (invariant)
    data[0x1020:0x1030] = struct.pack("<IIII",
                                       14, 1, 0, 0xDEADBEEF)

    # Region 0x1100-0x1300: More embedded hashes (FP for entropy)
    for i in range(8):
        h = hashlib.sha256(f"session_ticket_{i}".encode()).digest()
        off = 0x1100 + i * 40
        data[off:off + 32] = h

    # Region 0x2000-0x4000: Heap free list (low entropy, structural)
    for i in range(0x2000, 0x4000, 16):
        data[i:i + 8] = struct.pack("<Q", 0x0000000000000000)
        data[i + 8:i + 16] = struct.pack("<Q", 0x0000000000000041)

    # Region 0x8000-0xC000: More code (medium entropy)
    for i in range(0x8000, 0xC000):
        data[i] = code_patterns[0][(i - 0x8000) % 4]

    # Region 0xC000-0xE000: String table (low-medium entropy, invariant)
    strings = [b"SSL_CTX_new\x00", b"SSL_read\x00", b"SSL_write\x00",
               b"EVP_EncryptInit\x00", b"OPENSSL_init\x00"] * 50
    pos = 0xC000
    for s in strings:
        if pos + len(s) > 0xE000:
            break
        data[pos:pos + len(s)] = s
        pos += len(s)

    return data


def _add_per_run_noise(data: bytearray, run_idx: int,
                       rng: random.Random) -> dict:
    """Add per-run variable regions (these change between dumps).

    Returns dict of noise region info for ground truth.
    """
    noise = {}

    # Heap metadata: allocation timestamps, counters (LOW entropy, HIGH variance)
    # FP for variance-only
    for i in range(16):
        off = 0x500 + i * 32
        ts = 1700000000 + run_idx * 1000 + rng.randint(0, 999)
        counter = run_idx * 100 + i
        data[off:off + 8] = struct.pack("<Q", ts)
        data[off + 8:off + 12] = struct.pack("<I", counter)
    noise["heap_metadata"] = {"start": 0x500, "end": 0x700,
                              "count": 16, "type": "low_ent_high_var"}

    # ASLR pointers (MEDIUM entropy, HIGH variance)
    # FP for variance-only
    base = rng.randint(0x7F0000000000, 0x7FFFFFFFFFFF)
    for i in range(32):
        off = 0x4000 + i * 8
        ptr = base + rng.randint(0, 0xFFFF) * 8
        data[off:off + 8] = struct.pack("<Q", ptr)
    noise["pointers"] = {"start": 0x4000, "end": 0x4100,
                         "count": 32, "type": "med_ent_high_var"}

    # Random session IDs / nonces (HIGH entropy, HIGH variance)
    # FP for BOTH entropy and variance — hardest to eliminate
    for i in range(8):
        off = 0x6000 + i * 48
        session_id = rng.randbytes(32)
        data[off:off + 32] = session_id
        data[off + 32:off + 40] = struct.pack("<Q", run_idx)
    noise["session_ids"] = {"start": 0x6000, "end": 0x6180,
                            "count": 8, "type": "high_ent_high_var"}

    # TLS ticket keys / other crypto nonces (HIGH entropy, HIGH variance)
    for i in range(4):
        off = 0x7000 + i * 64
        data[off:off + 48] = rng.randbytes(48)  # 48-byte ticket key
    noise["ticket_keys"] = {"start": 0x7000, "end": 0x7100,
                            "count": 4, "type": "high_ent_high_var"}

    # Thread-local counters scattered in stack area
    for i in range(8):
        off = 0xE000 + i * 64
        data[off:off + 4] = struct.pack("<I", rng.randint(0, 0xFFFFFFFF))
    noise["stack_counters"] = {"start": 0xE000, "end": 0xE200,
                               "count": 8, "type": "low_ent_high_var"}

    return noise


def generate_dataset(output_dir: Path, num_runs: int = 30,
                     seed: int = 42) -> dict:
    """Generate realistic fixture dataset."""
    rng = random.Random(seed)
    output_dir = Path(output_dir)
    structural_base = _build_structural_base(seed)
    metadata = {"seed": seed, "num_runs": num_runs, "dump_size": DUMP_SIZE,
                "key_offset": KEY_OFFSET, "key_length": KEY_LENGTH,
                "tools": TOOL_NAMES, "runs": []}

    for tool in TOOL_NAMES:
        for run_idx in range(1, num_runs + 1):
            run_dir = output_dir / tool / f"{tool}_run_256_{run_idx}"
            run_dir.mkdir(parents=True, exist_ok=True)

            data = bytearray(structural_base)

            # Insert unique AES key per run
            key = rng.randbytes(KEY_LENGTH)
            data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH] = key

            # Add realistic per-run noise
            noise = _add_per_run_noise(data, run_idx, rng)

            dump_path = run_dir / f"{TIMESTAMP_BASE}_pre_snapshot.dump"
            dump_path.write_bytes(bytes(data))

            # Write keylog
            keylog = f"line\nAES256_KEY {'00' * 32} {key.hex()}\n"
            (run_dir / "keylog.csv").write_text(keylog)

            if tool == TOOL_NAMES[0]:
                run_meta = {
                    "run": run_idx, "key_hex": key.hex(),
                    "noise_regions": noise,
                    "iv_hex": VERIFICATION_IV.hex(),
                }
                # Add ciphertext for decryption verification if available
                try:
                    from tests.fixtures.decryption_verifier import (
                        create_verification_ciphertext,
                    )
                    ct = create_verification_ciphertext(key)
                    run_meta["ciphertext_hex"] = ct.hex()
                except ImportError:
                    pass
                metadata["runs"].append(run_meta)

    (output_dir / "metadata.json").write_text(
        __import__("json").dumps(metadata, indent=2))
    return metadata


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic memory dump fixtures")
    parser.add_argument("--output-dir", default="/tmp/realistic_fixtures")
    parser.add_argument("--num-runs", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    meta = generate_dataset(Path(args.output_dir), args.num_runs, args.seed)
    print(f"Generated {meta['num_runs']} runs for {len(meta['tools'])} tools")
    print(f"Dump size: {meta['dump_size']} bytes")
    print(f"Key at offset 0x{meta['key_offset']:04x}, {meta['key_length']}B")
    print(f"Output: {args.output_dir}")


if __name__ == "__main__":
    main()
