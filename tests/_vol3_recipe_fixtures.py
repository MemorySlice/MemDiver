"""Shared synthetic fixtures for the recipe-v2 / v2-template tests.

A synthetic "gocryptfs process": a buffer that holds a 32-byte master key
twice inside the neighbourhood shape the real Go heap shows (a length/cap
pair, 16 zero bytes, a 32-byte constant, the key, 32 zero bytes), between
deterministic pseudo-random filler. The vault is sealed by
``tests/_oracle_gocryptfs_fixtures`` (independent of the oracle under test).
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Tuple

from memdiver.architect import vol3_recipe as vr
from memdiver.oracles.formats import gocryptfs_gcm
from tests._oracle_gocryptfs_fixtures import (
    FEATURE_FLAGS,
    conf_json,
    content_key_ref,
    encrypt_file,
)

KIND = "gocryptfs-gcm"
MASTER = hashlib.sha256(b"memdiver synthetic master key").digest()
OTHER_MASTER = hashlib.sha256(b"some other vault").digest()
CONSTANT = bytes.fromhex("adde54f44f212597a0f2da90ea2812df0f75e564814192a32b934a82324ee0f8")
PREFIX = struct.pack("<QQ", 0x20, 0x60) + bytes(16) + CONSTANT
SUFFIX = bytes(32)
KEY_SITES = (0x4000, 0x9000)
BUFFER_SIZE = 0xC000


def filler(size: int, seed: bytes = b"filler") -> bytes:
    """Deterministic pseudo-random bytes, sparsely zeroed like a heap."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = hashlib.sha256(seed + counter.to_bytes(8, "little")).digest()
        out += block if counter % 4 else bytes(32)
        counter += 1
    return bytes(out[:size])


def process_buffer(master: bytes = MASTER, *, with_anchor: bool = True) -> bytes:
    """Filler with ``master`` at :data:`KEY_SITES` (8-aligned), anchor shape around it."""
    data = bytearray(filler(BUFFER_SIZE))
    for site in KEY_SITES:
        if with_anchor:
            data[site - len(PREFIX):site] = PREFIX
            data[site + 32:site + 64] = SUFFIX
        else:
            data[site - 32:site] = bytes(32)
            data[site + 32:site + 64] = bytes(32)
        data[site:site + 32] = master
    return bytes(data)


def vault(cipher: str = "aes-gcm", master: bytes = MASTER) -> Tuple[bytes, bytes]:
    """``(content_file, gocryptfs.conf)`` of a one-file synthetic vault."""
    content = encrypt_file(cipher, content_key_ref(master, cipher), b"hello memdiver\n" * 8)
    return content, conf_json(FEATURE_FLAGS[cipher])


def write_vault(directory: Path, cipher: str = "aes-gcm", master: bytes = MASTER) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    content, conf = vault(cipher, master)
    (directory / "gocryptfs.conf").write_bytes(conf)
    (directory / "gocryptfs.diriv").write_bytes(bytes(16))
    (directory / "AAAAAAAAAAAAAAAAAAAAAA").write_bytes(content)
    return directory


def sample(cipher: str = "aes-gcm", master: bytes = MASTER) -> bytes:
    content, conf = vault(cipher, master)
    return gocryptfs_gcm.make_sample(content, conf)


def anchor_pattern() -> str:
    tokens = [f"{b:02x}" for b in PREFIX] + ["??"] * 32 + [f"{b:02x}" for b in SUFFIX]
    return " ".join(tokens)


def synthetic_recipe(*, oracle_sample: bytes = None, with_oracle: bool = True,
                     pattern: str = None, name: str = "memdiver_gocryptfs_synth"
                     ) -> vr.PluginRecipe:
    oracle = None
    if with_oracle:
        oracle = vr.OracleSpec(KIND, {}, vr.OracleSample.from_bytes(
            oracle_sample if oracle_sample is not None else sample()))
    tokens = pattern or anchor_pattern()
    static = sum(t != "??" for t in tokens.split()) / len(tokens.split())
    return vr.PluginRecipe(
        name=name,
        class_name="MemDiverSynthGocryptfs",
        description="Synthetic gocryptfs master key (recipe v2 test fixture)",
        locators=(
            vr.Locator("anchor_regex", {"pattern": tokens, "static_ratio": round(static, 4),
                                        "max_hits": 64, "alignment": 1}),
            vr.Locator("entropy", {"threshold": 4.5, "mode": "fallback", "step": 8,
                                   "max_candidates": 100000}),
        ),
        decoder=vr.Decoder(len(PREFIX), 32),
        oracle=oracle,
        provenance={"generator": "tests/_vol3_recipe_fixtures.py"},
    )
