"""Regression tests: CLI reads MEMORY-relative offsets on .msl inputs.

`memdiver verify` and `memdiver export --offset/--length` receive offsets
that are MEMORY-relative for native `.msl` files — they come from
consensus/analysis over the flattened VAS projection, NOT from the raw
`.msl` container layout. Reading raw file bytes at those offsets silently
returns the wrong region (the byte at file offset 0x200 is not the byte at
memory offset 0x200 once the MSL headers/region structs shift the payload).

These tests pin the fix (tasks A5/A6): the CLI now opens dumps through
`core.dump_source.open_dump` and reads the memory projection, so a candidate
key planted at region-relative offset 0x200 is recovered at CLI offset 0x200
even though its flat-file offset is 0x2B8.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import memdiver.cli as cli
from memdiver.api.services.analysis_service import manual_export_pattern
from memdiver.engine.verification import (
    AesCbcVerifier,
    VERIFICATION_IV,
    VERIFICATION_PLAINTEXT,
)
from tests.fixtures.generate_msl_fixtures import write_aslr_fixture

# Region-relative offset where the fixture plants the 32-byte key. Its
# flat-file offset inside the MSL container is 0x2B8 (see
# test_auto_export_aslr_regression.py) — deliberately different so a raw
# file read at 0x200 cannot accidentally return the key.
KEY_REGION_OFFSET = 0x200
KEY_FILE_OFFSET = 64 + 80 + 32 + 8 + KEY_REGION_OFFSET  # 0x2B8
KEY_LENGTH = 32
FILLER_BYTE = 0x42

# A 32-byte key whose bytes are all distinct from the 0x42 filler, so the
# memory-projection read is unambiguously different from a raw-file read.
KEY_BYTES = bytes(range(1, 1 + KEY_LENGTH))  # 01 02 ... 20


def _verify_namespace(dump: Path, ciphertext_hex: str, output: Path) -> argparse.Namespace:
    """Build the argparse.Namespace `_cmd_verify` expects."""
    return argparse.Namespace(
        dump=str(dump),
        offset=KEY_REGION_OFFSET,
        length=KEY_LENGTH,
        ciphertext_hex=ciphertext_hex,
        iv_hex=None,
        cipher="AES-256-CBC",
        output=str(output),
        # decryption flags (unused here — plaintext fixture)
        key_file=None,
        passphrase=None,
        kem_key_file=None,
    )


def test_verify_reads_memory_relative_offset_on_msl(tmp_path):
    """`memdiver verify` recovers a key planted at the MEMORY offset.

    The raw file byte at offset 0x200 is filler (0x42), not the key — so a
    successful verify at 0x200 proves the candidate was read through the
    memory projection, not from raw container bytes.
    """
    msl = write_aslr_fixture(
        tmp_path / "verify.msl",
        region_base=0x7FFF00000000,
        key_offset=KEY_REGION_OFFSET,
        key_bytes=KEY_BYTES,
        filler_byte=FILLER_BYTE,
    )

    # Sanity: the raw file bytes at the same numeric offset are NOT the key,
    # so file-relative and memory-relative reads genuinely diverge.
    raw_at_offset = msl.read_bytes()[KEY_REGION_OFFSET:KEY_REGION_OFFSET + KEY_LENGTH]
    assert raw_at_offset != KEY_BYTES

    ciphertext = AesCbcVerifier().create_ciphertext(
        KEY_BYTES, VERIFICATION_PLAINTEXT, VERIFICATION_IV,
    )
    out = tmp_path / "verify_out.json"
    rc = cli._cmd_verify(_verify_namespace(msl, ciphertext.hex(), out))

    assert rc == 0
    result = json.loads(out.read_text())
    assert result["verified"] is True, result
    assert result["key_hex"] == KEY_BYTES.hex()


def test_manual_export_reads_memory_relative_offset_on_msl(tmp_path):
    """`manual_export_pattern` reads the region at the MEMORY offset (A6).

    Two identical native `.msl` dumps carry the same key at region offset
    0x200. The exported pattern's hex bytes must be the key (memory
    projection), NOT the 0x42 filler that sits at file offset 0x200.
    """
    paths = []
    for i in range(2):
        paths.append(write_aslr_fixture(
            tmp_path / f"exp_{i}.msl",
            region_base=0x7FFF00000000 + (i << 28),
            key_offset=KEY_REGION_OFFSET,
            key_bytes=KEY_BYTES,
            filler_byte=FILLER_BYTE,
        ))

    result = manual_export_pattern(
        paths,
        offset=KEY_REGION_OFFSET,
        length=KEY_LENGTH,
        fmt="json",
        name="mem_rel",
        min_static_ratio=0.3,
    )

    hex_pattern = result["pattern"]["hex_pattern"].replace(" ", "")
    assert hex_pattern == KEY_BYTES.hex(), (
        "Manual export read the wrong bytes — expected the memory-projection "
        f"key, got {hex_pattern}"
    )
    # Definitively not the raw-file filler that lives at file offset 0x200.
    assert hex_pattern != FILLER_BYTE.to_bytes(1, "little").hex() * KEY_LENGTH


def test_verify_subparser_accepts_decrypt_flags():
    """The `verify` subparser accepts --key-file/--passphrase/--kem-key-file."""
    parser = cli.build_parser()
    args = parser.parse_args([
        "verify", "some.msl",
        "--offset", "0x200",
        "--ciphertext-hex", "00",
        "--key-file", "k.bin",
        "--passphrase", "pw",
        "--kem-key-file", "kem.bin",
    ])
    assert args.key_file == "k.bin"
    assert args.passphrase == "pw"
    assert args.kem_key_file == "kem.bin"


def test_experiment_subparser_accepts_decrypt_flags():
    """The `experiment` subparser accepts the decryption flags too."""
    parser = cli.build_parser()
    args = parser.parse_args([
        "experiment",
        "--target", "t.py",
        "--key-file", "k.bin",
        "--passphrase", "pw",
        "--kem-key-file", "kem.bin",
    ])
    assert args.key_file == "k.bin"
    assert args.passphrase == "pw"
    assert args.kem_key_file == "kem.bin"
