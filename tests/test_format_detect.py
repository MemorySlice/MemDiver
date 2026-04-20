"""Tests for core.format_detect magic byte detection."""

import struct
import pytest
from core.format_detect import detect_format, detect_format_at_offset


class TestDetectFormat:
    def test_elf64(self):
        data = b"\x7fELF" + b"\x02" + b"\x00" * 59
        assert detect_format(data) == "elf64"

    def test_elf32(self):
        data = b"\x7fELF" + b"\x01" + b"\x00" * 47
        assert detect_format(data) == "elf32"

    def test_elf_unknown_class(self):
        data = b"\x7fELF" + b"\x00" + b"\x00" * 59
        assert detect_format(data) == "elf"

    def test_macho64_le(self):
        data = b"\xcf\xfa\xed\xfe" + b"\x00" * 28
        assert detect_format(data) == "macho64_le"

    def test_macho32_le(self):
        data = b"\xce\xfa\xed\xfe" + b"\x00" * 24
        assert detect_format(data) == "macho32_le"

    def test_macho64_be(self):
        data = b"\xfe\xed\xfa\xcf" + b"\x00" * 28
        assert detect_format(data) == "macho64_be"

    def test_macho32_be(self):
        data = b"\xfe\xed\xfa\xce" + b"\x00" * 24
        assert detect_format(data) == "macho32_be"

    def test_msl(self):
        data = b"MEMSLICE" + b"\x00" * 56
        assert detect_format(data) == "msl"

    def test_pe32(self):
        # MZ header + PE signature at offset 0x3C
        data = bytearray(256)
        data[0:2] = b"MZ"
        pe_off = 0x80
        struct.pack_into("<I", data, 0x3C, pe_off)
        data[pe_off:pe_off + 4] = b"PE\x00\x00"
        # Optional header magic for PE32
        opt_off = pe_off + 24
        struct.pack_into("<H", data, opt_off, 0x010B)
        assert detect_format(bytes(data)) == "pe32"

    def test_pe64(self):
        data = bytearray(256)
        data[0:2] = b"MZ"
        pe_off = 0x80
        struct.pack_into("<I", data, 0x3C, pe_off)
        data[pe_off:pe_off + 4] = b"PE\x00\x00"
        opt_off = pe_off + 24
        struct.pack_into("<H", data, opt_off, 0x020B)
        assert detect_format(bytes(data)) == "pe64"

    def test_sqlite3(self):
        data = b"SQLite format 3\x00" + b"\x00" * 84
        assert detect_format(data) == "sqlite3"

    def test_gzip(self):
        data = b"\x1f\x8b\x08\x00" + b"\x00" * 60
        assert detect_format(data) == "gzip"

    def test_zip(self):
        data = b"PK\x03\x04" + b"\x00" * 60
        assert detect_format(data) == "zip"

    def test_png(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56
        assert detect_format(data) == "png"

    def test_pdf(self):
        data = b"%PDF-1.7" + b"\x00" * 56
        assert detect_format(data) == "pdf"

    def test_java_class(self):
        # CAFEBABE with version 52.0 (Java 8)
        data = b"\xca\xfe\xba\xbe" + struct.pack(">I", 52) + b"\x00" * 56
        assert detect_format(data) == "java_class"

    def test_macho_fat(self):
        # CAFEBABE with 2 architectures (fat binary)
        data = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 56
        assert detect_format(data) == "macho_fat"

    def test_asn1_der(self):
        # DER sequence with 256-byte payload
        data = b"\x30\x82\x01\x00" + b"\x00" * 260
        assert detect_format(data) == "asn1_der"

    def test_asn1_der_too_small_length(self):
        # DER with very small length -- likely false positive, skip
        data = b"\x30\x82\x00\x20" + b"\x00" * 40
        assert detect_format(data) is None

    def test_unknown(self):
        data = b"\x00" * 64
        assert detect_format(data) is None

    def test_too_short(self):
        assert detect_format(b"\x7f") is None
        assert detect_format(b"") is None


class TestDetectFormatAtOffset:
    def test_elf_at_offset(self):
        prefix = b"\x00" * 100
        elf_data = b"\x7fELF\x02" + b"\x00" * 59
        data = prefix + elf_data
        assert detect_format_at_offset(data, 100) == "elf64"

    def test_no_format_at_offset(self):
        data = b"\x00" * 200
        assert detect_format_at_offset(data, 50) is None

    def test_negative_offset(self):
        data = b"\x7fELF" + b"\x00" * 60
        assert detect_format_at_offset(data, -1) is None

    def test_offset_beyond_data(self):
        data = b"\x7fELF" + b"\x00" * 60
        assert detect_format_at_offset(data, 100) is None
