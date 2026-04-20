"""Binary format detection from magic bytes."""

from __future__ import annotations
import struct
from typing import Optional

# Magic byte signatures: (offset, expected_bytes)
MAGIC_SIGNATURES: dict[str, tuple[int, bytes]] = {
    "elf": (0, b"\x7fELF"),
    "macho64_le": (0, b"\xcf\xfa\xed\xfe"),
    "macho32_le": (0, b"\xce\xfa\xed\xfe"),
    "macho64_be": (0, b"\xfe\xed\xfa\xcf"),
    "macho32_be": (0, b"\xfe\xed\xfa\xce"),
    "msl": (0, b"MEMSLICE"),
    "sqlite3": (0, b"SQLite format 3\x00"),
    "gzip": (0, b"\x1f\x8b"),
    "zip": (0, b"PK\x03\x04"),
    "png": (0, b"\x89PNG\r\n\x1a\n"),
    "pdf": (0, b"%PDF"),
}


def detect_format(data: bytes) -> Optional[str]:
    """Detect binary format from magic bytes at offset 0."""
    if len(data) < 4:
        return None

    # Check simple magic signatures
    for name, (off, magic) in MAGIC_SIGNATURES.items():
        end = off + len(magic)
        if len(data) >= end and data[off:end] == magic:
            if name == "elf":
                return _classify_elf(data)
            return name

    # PE: check for MZ + PE\0\0 at e_lfanew
    if data[:2] == b"MZ" and len(data) >= 64:
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if len(data) >= e_lfanew + 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return _classify_pe(data, e_lfanew)
        except struct.error:
            pass

    # Java class file vs Mach-O fat binary (both use 0xCAFEBABE)
    if len(data) >= 8 and data[:4] == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat <= 30:
            return "macho_fat"
        return "java_class"

    # ASN.1 DER sequence (common in PKCS, X.509 certificates)
    if len(data) >= 4 and data[0] == 0x30 and data[1] == 0x82:
        seq_len = struct.unpack_from(">H", data, 2)[0]
        if seq_len >= 64:
            return "asn1_der"

    return None


def _classify_elf(data: bytes) -> str:
    if len(data) >= 5:
        ei_class = data[4]
        if ei_class == 2:
            return "elf64"
        elif ei_class == 1:
            return "elf32"
    return "elf"


def _classify_pe(data: bytes, pe_offset: int) -> str:
    """Classify PE as pe32 or pe64 based on optional header magic."""
    coff_start = pe_offset + 4
    opt_start = coff_start + 20
    if len(data) >= opt_start + 2:
        magic = struct.unpack_from("<H", data, opt_start)[0]
        if magic == 0x020B:
            return "pe64"
    return "pe32"


def detect_format_at_offset(data: bytes, offset: int) -> Optional[str]:
    """Detect format at an arbitrary offset within a dump."""
    if offset < 0 or offset >= len(data):
        return None
    return detect_format(data[offset:])
