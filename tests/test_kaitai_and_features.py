"""Tests for Kaitai parsers, adapter, registry, and new API endpoints."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tests._paths import dataset_root, SKIP_REASON

# ---------------------------------------------------------------------------
# Synthetic binary helpers
# ---------------------------------------------------------------------------

_DS = dataset_root()
_REAL_DUMP = (
    _DS
    / "TLS13"
    / "20_iterations_Abort_KeyUpdate"
    / "boringssl"
    / "boringssl_run_13_10"
    / "20251013_131451_383028_pre_server_key_update.dump"
) if _DS is not None else None

has_real_dump = pytest.mark.skipif(
    _REAL_DUMP is None or not _REAL_DUMP.is_file(), reason=SKIP_REASON
)


def _make_elf64_le() -> bytes:
    """Minimal 64-byte ELF64 LE header (no sections/programs)."""
    buf = bytearray(64)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2       # ELFCLASS64
    buf[5] = 1       # ELFDATA2LSB
    buf[6] = 1       # EV_CURRENT
    buf[7] = 0       # ELFOSABI_NONE
    # pad bytes 8-15 already zero
    struct.pack_into("<H", buf, 16, 3)      # e_type = ET_DYN
    struct.pack_into("<H", buf, 18, 0x3E)   # e_machine = EM_X86_64
    struct.pack_into("<I", buf, 20, 1)      # e_version
    struct.pack_into("<Q", buf, 24, 0)      # e_entry
    struct.pack_into("<Q", buf, 32, 0)      # e_phoff
    struct.pack_into("<Q", buf, 40, 0)      # e_shoff
    struct.pack_into("<I", buf, 48, 0)      # e_flags
    struct.pack_into("<H", buf, 52, 64)     # e_ehsize
    struct.pack_into("<H", buf, 54, 0)      # e_phentsize
    struct.pack_into("<H", buf, 56, 0)      # e_phnum
    struct.pack_into("<H", buf, 58, 0)      # e_shentsize
    struct.pack_into("<H", buf, 60, 0)      # e_shnum
    struct.pack_into("<H", buf, 62, 0)      # e_shstrndx
    return bytes(buf)


def _make_pe_minimal() -> bytes:
    """Minimal PE with MZ header + PE signature + COFF header."""
    buf = bytearray(256)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew -> 0x80
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x8664)  # machine = AMD64
    struct.pack_into("<H", buf, 0x86, 0)        # num sections
    struct.pack_into("<I", buf, 0x88, 0)        # timestamp
    struct.pack_into("<I", buf, 0x8C, 0)        # symbol table ptr
    struct.pack_into("<I", buf, 0x90, 0)        # num symbols
    struct.pack_into("<H", buf, 0x94, 0)        # optional header size
    struct.pack_into("<H", buf, 0x96, 0)        # characteristics
    return bytes(buf)


def _make_macho64_le() -> bytes:
    """Minimal Mach-O 64-bit LE header."""
    buf = bytearray(64)
    struct.pack_into("<I", buf, 0, 0xFEEDFACF)  # MH_MAGIC_64
    struct.pack_into("<I", buf, 4, 0x01000007)   # CPU_TYPE_X86_64
    struct.pack_into("<I", buf, 8, 3)            # CPU_SUBTYPE_ALL
    struct.pack_into("<I", buf, 12, 2)           # MH_EXECUTE
    struct.pack_into("<I", buf, 16, 0)           # ncmds
    struct.pack_into("<I", buf, 20, 0)           # sizeofcmds
    struct.pack_into("<I", buf, 24, 0)           # flags
    struct.pack_into("<I", buf, 28, 0)           # reserved
    return bytes(buf)


# ===================================================================
# 1. Kaitai ELF Parser
# ===================================================================


class TestKaitaiElf:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_parse_elf64_header(self):
        from core.binary_formats.kaitai_compiled.elf import Elf

        obj = Elf.from_bytes(_make_elf64_le())
        assert obj.magic == b"\x7fELF"
        assert obj.bits == 2
        assert obj.endian == 1

    def test_debug_positions(self):
        from core.binary_formats.kaitai_compiled.elf import Elf

        obj = Elf.from_bytes(_make_elf64_le())
        assert "magic" in obj._debug
        assert obj._debug["magic"]["start"] == 0
        assert obj._debug["magic"]["end"] == 4

    def test_enum_decoding(self):
        from core.binary_formats.kaitai_compiled.elf import Elf, Machine, ObjType

        obj = Elf.from_bytes(_make_elf64_le())
        assert obj.header is not None
        assert obj.header.e_type == ObjType.ET_DYN
        assert obj.header.machine == Machine.EM_X86_64

    def test_truncated_data_no_crash(self):
        from core.binary_formats.kaitai_compiled.elf import Elf

        # Only first 20 bytes -- enough for magic + ident, header parse fails gracefully
        data = _make_elf64_le()[:20]
        obj = Elf.from_bytes(data)
        assert obj.magic == b"\x7fELF"
        # header may be None (partial parse)


# ===================================================================
# 2. Kaitai PE Parser
# ===================================================================


class TestKaitaiPe:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_parse_pe_dos_header(self):
        from core.binary_formats.kaitai_compiled.microsoft_pe import MicrosoftPe

        obj = MicrosoftPe.from_bytes(_make_pe_minimal())
        assert obj.dos_header.magic == b"MZ"
        assert obj.dos_header.ofs_pe == 0x80

    def test_pe_signature(self):
        from core.binary_formats.kaitai_compiled.microsoft_pe import MicrosoftPe

        obj = MicrosoftPe.from_bytes(_make_pe_minimal())
        assert obj.pe_signature == b"PE\x00\x00"

    def test_coff_machine(self):
        from core.binary_formats.kaitai_compiled.microsoft_pe import (
            MicrosoftPe,
            PeMachine,
        )

        obj = MicrosoftPe.from_bytes(_make_pe_minimal())
        assert obj.coff_header is not None
        assert obj.coff_header.machine == PeMachine.AMD64


# ===================================================================
# 3. Kaitai Mach-O Parser
# ===================================================================


class TestKaitaiMachO:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_parse_macho64(self):
        from core.binary_formats.kaitai_compiled.mach_o import CpuType, FileType, MachO

        obj = MachO.from_bytes(_make_macho64_le())
        assert obj.cputype == CpuType.X86_64
        assert obj.filetype == FileType.EXECUTE
        assert obj.ncmds == 0


# ===================================================================
# 4. Kaitai Adapter
# ===================================================================


class TestKaitaiAdapter:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_walk_fields_returns_overlays(self):
        from core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter
        from core.binary_formats.kaitai_compiled.elf import Elf

        obj = Elf.from_bytes(_make_elf64_le())
        adapter = KaitaiOverlayAdapter()
        overlays = adapter.walk_fields(obj)
        assert len(overlays) > 0

    def test_overlay_attributes(self):
        from core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter
        from core.binary_formats.kaitai_compiled.elf import Elf

        obj = Elf.from_bytes(_make_elf64_le())
        adapter = KaitaiOverlayAdapter()
        overlays = adapter.walk_fields(obj)
        first = overlays[0]
        assert hasattr(first, "field_name")
        assert hasattr(first, "offset")
        assert hasattr(first, "length")
        assert hasattr(first, "display")
        assert hasattr(first, "path")
        assert isinstance(first.offset, int)
        assert isinstance(first.length, int)

    def test_intenum_display(self):
        from core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter
        from core.binary_formats.kaitai_compiled.elf import Elf

        obj = Elf.from_bytes(_make_elf64_le())
        adapter = KaitaiOverlayAdapter()
        overlays = adapter.walk_fields(obj)
        # Find machine field overlay -- should show "62 (EM_X86_64)"
        machine_overlays = [o for o in overlays if "machine" in o.path]
        assert len(machine_overlays) >= 1
        assert "EM_X86_64" in machine_overlays[0].display


# ===================================================================
# 5. Kaitai Registry
# ===================================================================


class TestKaitaiRegistry:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_kaitai_available(self):
        from core.binary_formats.kaitai_registry import kaitai_available

        assert kaitai_available() is True

    def test_available_formats(self):
        from core.binary_formats.kaitai_registry import get_kaitai_registry

        reg = get_kaitai_registry()
        fmts = reg.available_formats()
        assert "elf64" in fmts
        assert "pe" in fmts
        assert "macho" in fmts

    def test_parse_elf64(self):
        from core.binary_formats.kaitai_registry import get_kaitai_registry

        reg = get_kaitai_registry()
        obj = reg.parse("elf64", _make_elf64_le())
        assert obj is not None
        assert obj.magic == b"\x7fELF"

    def test_parse_unknown_returns_none(self):
        from core.binary_formats.kaitai_registry import get_kaitai_registry

        reg = get_kaitai_registry()
        assert reg.parse("unknown_format", b"\x00" * 64) is None


# ===================================================================
# 6-9. FastAPI endpoint tests
# ===================================================================


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from api.main import create_app

    app = create_app()
    return TestClient(app)


class TestFormatEndpoint:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    @has_real_dump
    def test_format_on_real_dump(self, client):
        resp = client.get("/api/inspect/format", params={"dump_path": str(_REAL_DUMP)})
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "elf64"
        assert data["nav_tree"] is not None
        assert data["overlays"] is not None
        assert len(data["overlays"]["fields"]) > 0

    @has_real_dump
    def test_structure_apply_returns_200(self, client):
        resp = client.get(
            "/api/inspect/structure-apply",
            params={"dump_path": str(_REAL_DUMP), "offset": 0, "structure_name": "tls13_record"},
        )
        # Should succeed (200) or 404 if structure not found -- not 400
        assert resp.status_code in (200, 404)


class TestArchitectEndpoints:
    def test_check_static_invalid_paths(self, client):
        resp = client.post(
            "/api/architect/check-static",
            json={"dump_paths": ["/nonexistent/a.dump", "/nonexistent/b.dump"], "offset": 0, "length": 16},
        )
        assert resp.status_code == 404

    def test_generate_pattern_empty_data(self, client):
        resp = client.post(
            "/api/architect/generate-pattern",
            json={"reference_hex": "", "static_mask": [], "name": "test"},
        )
        assert resp.status_code == 400

    def test_export_yara(self, client):
        pattern = {
            "name": "test_pat",
            "wildcard_hex": "7f 45 4c 46 ?? ?? 01",
            "byte_length": 7,
            "static_count": 5,
        }
        resp = client.post(
            "/api/architect/export",
            json={"pattern": pattern, "format": "yara", "rule_name": "test_rule"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "yara"
        assert "content" in data


class TestPatternsEndpoint:
    def test_list_patterns(self, client):
        resp = client.get("/api/analysis/patterns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["patterns"]) >= 3


class TestNotebookStatus:
    def test_notebook_status(self, client):
        resp = client.get("/api/notebook/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "available" in data


# ===================================================================
# 10. KSY Import Endpoint
# ===================================================================


class TestKsyImport:
    def test_valid_ksy_upload(self, client):
        ksy_content = (
            "meta:\n"
            "  id: test_format\n"
            "seq:\n"
            "  - id: magic\n"
            "    size: 4\n"
        )
        resp = client.post(
            "/api/structures/import-ksy",
            files={"file": ("test_format.ksy", ksy_content.encode(), "application/octet-stream")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "test_format"

    def test_invalid_yaml_returns_400(self, client):
        bad_yaml = ":\n  - :\n  bad: [unterminated"
        resp = client.post(
            "/api/structures/import-ksy",
            files={"file": ("bad.ksy", bad_yaml.encode(), "application/octet-stream")},
        )
        assert resp.status_code == 400


# ===================================================================
# 11. Custom Patterns Round-Trip
# ===================================================================


class TestCustomPatternsRoundTrip:
    @has_real_dump
    def test_run_file_with_custom_patterns(self, client):
        pattern = {
            "name": "test_custom",
            "wildcard_hex": "7f 45 4c 46",
            "byte_length": 4,
            "static_count": 4,
        }
        resp = client.post(
            "/api/analysis/run-file",
            json={
                "dump_path": str(_REAL_DUMP),
                "algorithms": ["pattern_match"],
                "custom_patterns": [pattern],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "libraries" in data
        assert len(data["libraries"]) == 1


# ===================================================================
# 12. Mach-O Detection Round-Trip
# ===================================================================


class TestMachoDetectionRoundTrip:
    @pytest.fixture(autouse=True)
    def _require_kaitai(self):
        pytest.importorskip("kaitaistruct")

    def test_detect_parse_and_overlay(self):
        from core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter
        from core.binary_formats.kaitai_registry import get_kaitai_registry
        from core.format_detect import detect_format

        data = _make_macho64_le()

        # Step 1: detect format
        fmt = detect_format(data)
        assert fmt == "macho64_le"

        # Step 2: parse via registry
        registry = get_kaitai_registry()
        parsed = registry.parse("macho64_le", data)
        assert parsed is not None

        # Step 3: walk fields via adapter
        adapter = KaitaiOverlayAdapter()
        overlays = adapter.walk_fields(parsed)
        assert len(overlays) > 0
        # Verify overlay entries have expected attributes
        for ov in overlays:
            assert hasattr(ov, "offset")
            assert hasattr(ov, "length")
            assert hasattr(ov, "field_name")


# ===================================================================
# 13. Session Restore Preserves Algorithm Grouping
# ===================================================================


class TestSessionRestoreGrouping:
    def test_save_and_load_preserves_hit_types(self, client):
        session_name = "_test_grouping_roundtrip"

        # Build an analysis_result with hits from two different algorithms
        analysis_result = {
            "libraries": [
                {
                    "library": "test_lib",
                    "protocol_version": "unknown",
                    "phase": "file",
                    "num_runs": 1,
                    "hits": [
                        {
                            "secret_type": "entropy_scan",
                            "offset": 100,
                            "length": 32,
                            "dump_path": "/tmp/fake.dump",
                            "library": "test_lib",
                            "phase": "file",
                            "run_id": 0,
                            "confidence": 0.9,
                        },
                        {
                            "secret_type": "change_point",
                            "offset": 500,
                            "length": 48,
                            "dump_path": "/tmp/fake.dump",
                            "library": "test_lib",
                            "phase": "file",
                            "run_id": 0,
                            "confidence": 0.7,
                        },
                    ],
                    "static_regions": [],
                    "metadata": {},
                }
            ],
            "metadata": {},
        }

        # Save session
        resp = client.post(
            "/api/sessions/",
            json={
                "session_name": session_name,
                "analysis_result": analysis_result,
            },
        )
        assert resp.status_code == 200

        try:
            # Load session back
            resp = client.get(f"/api/sessions/{session_name}")
            assert resp.status_code == 200
            loaded = resp.json()

            # Verify hits preserve their algorithm grouping
            hits = loaded["analysis_result"]["libraries"][0]["hits"]
            secret_types = {h["secret_type"] for h in hits}
            assert "entropy_scan" in secret_types
            assert "change_point" in secret_types
        finally:
            # Cleanup
            client.delete(f"/api/sessions/{session_name}")
