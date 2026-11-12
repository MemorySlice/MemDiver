"""Recognise a filesystem / volume head in decrypted block-device bytes (no crypto here).

A recovered dm-crypt key is proven by decrypting the first units of the device and finding
a well-formed filesystem head.  ``classify`` scores how much STRUCTURE matched, in bits: the
number of bits a uniformly random input would have to hit by chance (rounded down, and an
alternative between ``n`` accepted values costs ``log2(n)`` bits).  ``best_match(...,
min_bits=64)`` is the proof threshold.  ``PROBES`` lists the byte offsets whose blocks a
prefilter should decrypt first (``(fs, byte_offset, magic)``).

``extents`` maps a byte offset on the decrypted device to the bytes there (e.g. ``{0:
first_4k, 0x10000: btrfs_sb}``); fields that are not covered are simply not checked.  An
all-zero extent contributes NOTHING: it is never proof (no magic is zero) and never a
rejection (an optional checksum that falls in it is skipped).

Bits per filesystem (conservative):

=========  ====================================================================  ==========
ext2/3/4   magic 0xEF53 @0x438 (16) + s_rev_level in {0,1} (31) + s_log_block_   76 / 108
           size <= 6 (29) + s_first_data_block == (1 if 1 KiB blocks else 0)
           (counted as 0: dependent) ; metadata_csum: crc32c @0x7FC (+32)
XFS        'XFSB' @0 (32) + sb_blocksize power of two in 512..64K (29) +          73 / 105
           sb_sectsize power of two in 512..32K (12); v5: sb_crc @224 (+32)
FAT        0x55AA @510 (16) + jump EB??90 / E9 (8) + bytes/sector in              99
           {512,1024,2048,4096} (14) + 'FAT12/16/32   ' @0x36 or 0x52 (61)
NTFS       'NTFS    ' @3 (64) + 0x55AA @510 (16)                                  80
LVM2       'LABELONE' in sector 0..3 (62) + 'LVM2 001' @+0x18 (64)                126
swap       'SWAPSPACE2' / 'SWAP-SPACE' @0xFF6 (79)                                79
GPT        'EFI PART' @0x200 (64) + header CRC32 (32)                             96
btrfs      '_BHRfS_M' @0x10040 (64) ; crc32c of the 4 KiB superblock (+32)        64 / 96
=========  ====================================================================  ==========

Self-contained: standard library only, paste-safe (no relative import, no ``__file__``),
Python 3.8.
"""

import struct
import zlib
from typing import Dict, List, NamedTuple, Optional, Tuple

_FSM_EXT4_SB = 0x400
_FSM_BTRFS_SB = 0x10000
_FSM_FAT_TYPES = (b"FAT12   ", b"FAT16   ", b"FAT32   ")
_FSM_SWAP_MAGICS = (b"SWAPSPACE2", b"SWAP-SPACE")
_FSM_CRC32C_POLY = 0x82F63B78  # Castagnoli, reflected

PROBES: Tuple[Tuple[str, int, bytes], ...] = (
    ("ext4", 0x438, b"\x53\xef"),
    ("xfs", 0x0, b"XFSB"),
    ("vfat", 0x1FE, b"\x55\xaa"),
    ("ntfs", 0x3, b"NTFS    "),
    ("lvm2", 0x200, b"LABELONE"),
    ("swap", 0xFF6, b"SWAPSPACE2"),
    ("swap", 0xFF6, b"SWAP-SPACE"),
    ("gpt", 0x200, b"EFI PART"),
    ("btrfs", 0x10040, b"_BHRfS_M"),
)


class Match(NamedTuple):
    """One recognised head: filesystem name, matched bits, human-readable evidence."""

    fs: str
    bits: int
    detail: str


def _fsm_crc32c_table() -> Tuple[int, ...]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ _FSM_CRC32C_POLY if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_FSM_CRC32C_TABLE = _fsm_crc32c_table()


def crc32c(data, crc: int = 0) -> int:
    """Standard CRC-32C (Castagnoli; ``crc32c(b"123456789") == 0xE3069283``).

    ``crc`` continues a previous result, like ``zlib.crc32``.  The kernel's raw
    ``crc32c(~0, buf)`` (ext4 superblock checksum) is ``crc32c(buf) ^ 0xFFFFFFFF``.
    """
    table = _FSM_CRC32C_TABLE
    crc ^= 0xFFFFFFFF
    for byte in bytes(data):
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _fsm_nonzero(extents: Dict[int, bytes]) -> Dict[int, bytes]:
    return {int(off): bytes(buf) for off, buf in extents.items() if buf and any(buf)}


def _fsm_read(extents: Dict[int, bytes], offset: int, length: int) -> Optional[bytes]:
    """``length`` bytes at device ``offset`` from ONE extent that covers them, else None."""
    for start, buf in extents.items():
        if start <= offset and offset + length <= start + len(buf):
            return buf[offset - start: offset - start + length]
    return None


def _fsm_u16(extents, offset: int, fmt: str = "<H") -> Optional[int]:
    raw = _fsm_read(extents, offset, 2)
    return None if raw is None else struct.unpack(fmt, raw)[0]


def _fsm_u32(extents, offset: int, fmt: str = "<I") -> Optional[int]:
    raw = _fsm_read(extents, offset, 4)
    return None if raw is None else struct.unpack(fmt, raw)[0]


def _fsm_pow2(value: Optional[int], low: int, high: int) -> bool:
    return value is not None and low <= value <= high and not value & (value - 1)


def _fsm_ext4(extents) -> Optional[Match]:
    sb = _fsm_read(extents, _FSM_EXT4_SB, 0x400)
    if sb is None or sb[0x38:0x3A] != b"\x53\xef":
        return None
    first_data, log_block, rev = struct.unpack_from("<I", sb, 0x14)[0], struct.unpack_from(
        "<I", sb, 0x18)[0], struct.unpack_from("<I", sb, 0x4C)[0]
    if rev not in (0, 1) or log_block > 6 or first_data != (1 if log_block == 0 else 0):
        return None
    bits, detail = 76, "ext magic, rev %d, %d-byte blocks" % (rev, 1024 << log_block)
    ro_compat = struct.unpack_from("<I", sb, 0x64)[0]
    if ro_compat & 0x400:  # EXT4_FEATURE_RO_COMPAT_METADATA_CSUM
        stored = struct.unpack_from("<I", sb, 0x3FC)[0]
        if stored != crc32c(sb[:0x3FC]) ^ 0xFFFFFFFF:
            return None
        bits, detail = bits + 32, detail + ", metadata_csum crc32c ok"
    return Match("ext4", bits, detail)


def _fsm_xfs(extents) -> Optional[Match]:
    sb = _fsm_read(extents, 0, 512)
    if sb is None or sb[:4] != b"XFSB":
        return None
    blocksize = struct.unpack_from(">I", sb, 4)[0]
    sectsize = struct.unpack_from(">H", sb, 102)[0]
    if not (_fsm_pow2(blocksize, 512, 65536) and _fsm_pow2(sectsize, 512, 32768)):
        return None
    bits, detail = 73, "XFSB, %d-byte blocks, %d-byte sectors" % (blocksize, sectsize)
    if struct.unpack_from(">H", sb, 100)[0] & 0xF == 5:
        whole = _fsm_read(extents, 0, sectsize)
        if whole is not None:
            zeroed = whole[:224] + bytes(4) + whole[228:]
            if struct.unpack_from("<I", whole, 224)[0] != crc32c(zeroed):
                return None
            bits, detail = bits + 32, detail + ", v5 sb_crc ok"
    return Match("xfs", bits, detail)


def _fsm_fat(extents) -> Optional[Match]:
    boot = _fsm_read(extents, 0, 512)
    if boot is None or boot[510:512] != b"\x55\xaa":
        return None
    if not (boot[0] == 0xE9 or (boot[0] == 0xEB and boot[2] == 0x90)):
        return None
    if struct.unpack_from("<H", boot, 11)[0] not in (512, 1024, 2048, 4096):
        return None
    for where in (0x36, 0x52):
        if boot[where: where + 8] in _FSM_FAT_TYPES:
            name = boot[where: where + 8].decode("ascii").strip()
            return Match("vfat", 99, "%s boot sector, type @%#x" % (name, where))
    return None


def _fsm_ntfs(extents) -> Optional[Match]:
    boot = _fsm_read(extents, 0, 512)
    if boot is None or boot[3:11] != b"NTFS    " or boot[510:512] != b"\x55\xaa":
        return None
    return Match("ntfs", 80, "NTFS boot sector")


def _fsm_lvm2(extents) -> Optional[Match]:
    for sector in range(4):
        label = _fsm_read(extents, sector * 512, 0x20)
        if label is not None and label[:8] == b"LABELONE" and label[0x18:0x20] == b"LVM2 001":
            return Match("lvm2", 126, "LVM2 label in sector %d" % sector)
    return None


def _fsm_swap(extents) -> Optional[Match]:
    magic = _fsm_read(extents, 0xFF6, 10)
    if magic in _FSM_SWAP_MAGICS:
        return Match("swap", 79, "Linux swap %s" % magic.decode("ascii"))
    return None


def _fsm_gpt(extents) -> Optional[Match]:
    header = _fsm_read(extents, 0x200, 92)
    if header is None or header[:8] != b"EFI PART":
        return None
    size = struct.unpack_from("<I", header, 12)[0]
    full = _fsm_read(extents, 0x200, size) if 92 <= size <= 512 else None
    if full is None:
        return None
    zeroed = full[:16] + bytes(4) + full[20:]
    if struct.unpack_from("<I", full, 16)[0] != zlib.crc32(zeroed) & 0xFFFFFFFF:
        return None
    return Match("gpt", 96, "GPT header, crc32 ok")


def _fsm_btrfs(extents) -> Optional[Match]:
    if _fsm_read(extents, _FSM_BTRFS_SB + 0x40, 8) != b"_BHRfS_M":
        return None
    sb = _fsm_read(extents, _FSM_BTRFS_SB, 0x1000)
    if sb is None or struct.unpack_from("<H", sb, 0xC0)[0] != 0:  # csum_type 0 = crc32c
        return Match("btrfs", 64, "btrfs magic")
    if struct.unpack_from("<I", sb, 0)[0] != crc32c(sb[0x20:]):
        return None
    return Match("btrfs", 96, "btrfs magic, superblock crc32c ok")


_FSM_CHECKS = (_fsm_ext4, _fsm_xfs, _fsm_fat, _fsm_ntfs, _fsm_lvm2, _fsm_swap, _fsm_gpt, _fsm_btrfs)


def classify(extents: Dict[int, bytes]) -> List[Match]:
    """Every head recognised in ``extents`` (device offset -> bytes), most bits first."""
    present = _fsm_nonzero(extents)
    found = [match for match in (check(present) for check in _FSM_CHECKS) if match is not None]
    return sorted(found, key=lambda match: -match.bits)


def best_match(extents: Dict[int, bytes], min_bits: int = 64) -> Optional[Match]:
    """The strongest match with at least ``min_bits`` bits, else None."""
    found = classify(extents)
    return found[0] if found and found[0].bits >= min_bits else None
