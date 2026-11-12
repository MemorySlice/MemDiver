"""vol3plugins/linux/secrets/fsmagic.py against real mkfs output and random data.

The fixtures in tests/fixtures/fsmagic/ are the first 4 KiB of images made by the real tools
(mkfs.ext4, mkfs.xfs, mkfs.vfat, mkntfs, pvcreate, mkswap, sgdisk, mkfs.btrfs; versions and
commands: tests/fixtures/fsmagic/README.txt) plus btrfs's 4 KiB primary superblock at 64 KiB.
"""

import os
import random
import struct
import zlib
from pathlib import Path

import pytest

from memdiver.vol3plugins.linux.secrets import fsmagic

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fsmagic"

EXPECTED = {  # fixture -> (fs, bits)
    "ext4_csum": ("ext4", 108),
    "ext4_nocsum": ("ext4", 76),
    "ext4_1k": ("ext4", 76),
    "xfs_v5": ("xfs", 105),
    "vfat16": ("vfat", 99),
    "vfat32": ("vfat", 99),
    "ntfs": ("ntfs", 80),
    "lvm2": ("lvm2", 126),
    "swap": ("swap", 79),
    "gpt": ("gpt", 96),
}


def _head(name):
    path = FIXTURES / ("%s.head4k.bin" % name)
    if not path.exists():
        pytest.skip("fixture %s was not generated (tool unavailable)" % path.name)
    data = path.read_bytes()
    assert len(data) == 4096
    return data


def test_crc32c_known_answers():
    assert fsmagic.crc32c(b"123456789") == 0xE3069283
    assert fsmagic.crc32c(b"") == 0
    assert fsmagic.crc32c(bytes(32)) == 0x8A9136AA  # RFC 3720 B.4
    assert fsmagic.crc32c(b"\xff" * 32) == 0x62A8AB43
    assert fsmagic.crc32c(b"6789", fsmagic.crc32c(b"12345")) == 0xE3069283


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_heads_are_classified(name):
    fs, bits = EXPECTED[name]
    best = fsmagic.best_match({0: _head(name)})
    assert best is not None and (best.fs, best.bits) == (fs, bits), fsmagic.classify({0: _head(name)})


def test_real_btrfs_superblock():
    sb = (FIXTURES / "btrfs.sb64k.bin").read_bytes()
    assert fsmagic.best_match({0: _head("btrfs"), 0x10000: sb}) == fsmagic.Match(
        "btrfs", 96, "btrfs magic, superblock crc32c ok")
    only_magic = {0x10000 + 0x40: sb[0x40:0x48]}  # just the magic: 64 bits, still a proof
    assert fsmagic.best_match(only_magic).bits == 64
    corrupt = sb[:0x100] + bytes([sb[0x100] ^ 1]) + sb[0x101:]
    assert fsmagic.classify({0x10000: corrupt}) == []


@pytest.mark.parametrize("name", ["ext4_csum", "xfs_v5", "gpt"])
def test_a_flipped_bit_under_the_checksum_rejects(name):
    head = bytearray(_head(name))
    target = {"ext4_csum": 0x400 + 0x100, "xfs_v5": 0x60, "gpt": 0x200 + 0x30}[name]
    head[target] ^= 1
    assert fsmagic.classify({0: bytes(head)}) == []


def test_checksums_are_skipped_when_the_bytes_are_not_there():
    head = _head("ext4_csum")
    partial = {0x400: head[0x400:0x600]}  # the magic area but not the whole superblock
    assert fsmagic.classify(partial) == []  # ext4 needs the 1 KiB superblock
    whole_sb = {0x400: head[0x400:0x800]}
    assert fsmagic.best_match(whole_sb).bits == 108
    xfs = _head("xfs_v5")
    assert fsmagic.best_match({0: xfs[:512]}).bits == 105


def test_extents_at_other_offsets_and_zero_extents():
    head = _head("vfat32")
    extents = {0: head[:512], 4096: bytes(4096), 0x10000: bytes(4096)}
    assert fsmagic.best_match(extents).fs == "vfat"
    assert fsmagic.classify({0: bytes(4096)}) == []
    assert fsmagic.classify({0: bytes(4096), 0x10000: bytes(4096)}) == []
    assert fsmagic.best_match({}) is None


def test_zero_extent_never_rejects_an_optional_checksum():
    """btrfs magic in one extent, the rest of its superblock all zero: magic-only, not rejection."""
    sb = (FIXTURES / "btrfs.sb64k.bin").read_bytes()
    extents = {0x10040: sb[0x40:0x48], 0x10000: bytes(0x1000)}
    assert fsmagic.best_match(extents).bits == 64


def test_min_bits_threshold():
    head = _head("ntfs")
    assert fsmagic.best_match({0: head}, min_bits=80).fs == "ntfs"
    assert fsmagic.best_match({0: head}, min_bits=81) is None


def test_probes_point_at_each_magic():
    names = {fs for fs, _, _ in fsmagic.PROBES}
    assert names == {"ext4", "xfs", "vfat", "ntfs", "lvm2", "swap", "gpt", "btrfs"}
    for name, (fs, _) in EXPECTED.items():
        head = _head(name)
        assert any(head[off: off + len(magic)] == magic for probe_fs, off, magic in fsmagic.PROBES
                   if probe_fs == fs and off + len(magic) <= 4096), name


def test_synthetic_variants():
    fat = bytearray(512)
    fat[0], fat[11:13], fat[0x36:0x3E], fat[510:512] = 0xE9, struct.pack("<H", 2048), b"FAT12   ", b"\x55\xaa"
    assert fsmagic.best_match({0: bytes(fat)}).detail.startswith("FAT12")
    fat[11:13] = struct.pack("<H", 4097)
    assert fsmagic.classify({0: bytes(fat)}) == []
    swap = bytearray(4096)
    swap[0xFF6:] = b"SWAP-SPACE"
    assert fsmagic.best_match({0: bytes(swap)}).fs == "swap"
    lvm = bytearray(4096)
    lvm[0x600:0x608], lvm[0x618:0x620] = b"LABELONE", b"LVM2 001"  # label in sector 3
    assert fsmagic.best_match({0: bytes(lvm)}).detail == "LVM2 label in sector 3"
    gpt = bytearray(1024)
    gpt[0x200:0x208] = b"EFI PART"
    struct.pack_into("<I", gpt, 0x20C, 92)
    struct.pack_into("<I", gpt, 0x210, zlib.crc32(bytes(gpt[0x200:0x25C])))
    assert fsmagic.best_match({0: bytes(gpt)}).fs == "gpt"
    struct.pack_into("<I", gpt, 0x20C, 4096)  # header size the extent cannot hold
    assert fsmagic.classify({0: bytes(gpt)}) == []


def test_random_buffers_never_match():
    rng = random.Random(0xF5)
    seed = os.urandom(16)
    for i in range(100000):
        buf = rng.getrandbits(4096 * 8).to_bytes(4096, "little")
        assert fsmagic.best_match({0: buf}) is None, (seed.hex(), i)


def test_random_buffers_with_planted_magic_only_stay_below_threshold():
    """Magic alone is not proof for the formats whose magic is short."""
    rng = random.Random(7)
    for _ in range(2000):
        buf = bytearray(rng.getrandbits(4096 * 8).to_bytes(4096, "little"))
        buf[0x438:0x43A], buf[510:512], buf[0:4] = b"\x53\xef", b"\x55\xaa", b"XFSB"
        assert fsmagic.best_match({0: bytes(buf)}) is None
