"""Spec §4.2.1 compressed-payload framing, legacy read support and
memslicer interoperability for :mod:`memdiver.msl.compress`."""

import io
import os
import struct
import sys
from pathlib import Path

import pytest

from memdiver.msl import compress as compress_mod
from memdiver.msl.compress import compress, decompress
from memdiver.msl.enums import CompAlgo
from memdiver.msl.reader import MslReader
from memdiver.msl.types import MslParseError
from memdiver.msl.writer import MslWriter

zstandard = pytest.importorskip("zstandard")
lz4_block = pytest.importorskip("lz4.block")
lz4_frame = pytest.importorskip("lz4.frame")

CODECS = [CompAlgo.ZSTD, CompAlgo.LZ4]
ZSTD_MAGIC = b"\x28\xB5\x2F\xFD"
LZ4_FRAME_MAGIC = b"\x04\x22\x4D\x18"
MEMSLICER_SRC = Path(__file__).resolve().parents[2] / "memslicer" / "src"


def _legacy_compress(payload: bytes, algo: CompAlgo) -> bytes:
    """Frozen pre-spec MemDiver encoder: bare zstd frame / lz4 frame."""
    if algo == CompAlgo.ZSTD:
        return zstandard.ZstdCompressor().compress(payload)
    return lz4_frame.compress(payload)


def _region_bytes(reader, region) -> bytes:
    """Captured page bytes of a (possibly compressed) region block."""
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    return reader.read_block_payload(region.block_header)[0x20 + map_bytes:]


def _sample(n: int = 4096) -> bytes:
    return os.urandom(64) + b"\x5A" * (n - 64)


# ---------------------------------------------------------------- spec framing


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_compress_emits_size_prefix(algo):
    data = _sample()
    framed = compress(data, algo)
    assert struct.unpack_from("<Q", framed)[0] == len(data)
    if algo == CompAlgo.ZSTD:
        assert framed[8:12] == ZSTD_MAGIC
        assert framed[8:] == zstandard.ZstdCompressor().compress(data)
    else:  # lz4 block with 4-byte stored size, exactly like memslicer
        assert framed[8:] == lz4_block.compress(data, store_size=True)


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
@pytest.mark.parametrize("size", [0, 1, 7, 4096, 3 * 4096 + 8])
def test_spec_roundtrip(algo, size):
    data = _sample(size) if size >= 64 else os.urandom(size)
    assert decompress(compress(data, algo), algo) == data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
@pytest.mark.parametrize("pad", range(1, 8))
def test_spec_tolerates_memslicer_zero_padding(algo, pad):
    data = _sample()
    assert decompress(compress(data, algo) + b"\x00" * pad, algo) == data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
@pytest.mark.parametrize("delta", [-1, 1])
def test_size_mismatch_rejected(algo, delta):
    data = _sample()
    framed = bytearray(compress(data, algo))
    struct.pack_into("<Q", framed, 0, len(data) + delta)
    with pytest.raises(MslParseError, match="mismatch"):
        decompress(bytes(framed), algo)


def test_zstd_frame_without_content_size_mismatch_rejected():
    data = _sample()
    cctx = zstandard.ZstdCompressor(write_content_size=False)
    framed = struct.pack("<Q", len(data) + 8) + cctx.compress(data)
    with pytest.raises(MslParseError, match="mismatch"):
        decompress(framed, CompAlgo.ZSTD)
    ok = struct.pack("<Q", len(data)) + cctx.compress(data)
    assert decompress(ok, CompAlgo.ZSTD) == data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_truncated_prefix_rejected(algo):
    with pytest.raises(MslParseError):
        decompress(b"\x01\x02\x03", algo)


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_truncated_spec_stream_rejected(algo):
    framed = compress(_sample(), algo)
    with pytest.raises(MslParseError):
        decompress(framed[:len(framed) // 2], algo)


# ---------------------------------------------------------------- legacy read


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_legacy_payload_still_decodes(algo):
    data = _sample()
    legacy = _legacy_compress(data, algo)
    assert compress_mod._is_legacy_payload(legacy, algo)
    assert decompress(legacy, algo) == data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_spec_payload_never_classified_legacy(algo):
    assert not compress_mod._is_legacy_payload(compress(_sample(), algo), algo)


def test_zstd_prefix_colliding_with_frame_magic_is_spec():
    """UncompressedSize whose low 32 bits equal the zstd magic still decodes
    as spec: the magic at offset 8 disambiguates."""
    fake = struct.pack("<Q", 0x1_FD2FB528) + zstandard.ZstdCompressor().compress(b"x")
    assert fake[:4] == ZSTD_MAGIC
    assert not compress_mod._is_legacy_payload(fake, CompAlgo.ZSTD)
    with pytest.raises(MslParseError, match="mismatch"):
        decompress(fake, CompAlgo.ZSTD)


def test_lz4_prefix_colliding_with_frame_magic_is_spec():
    """A spec lz4 size equal to the lz4 frame magic has byte 4 == 0 (the u32
    stored size bounds it), which a legacy lz4 frame (FLG) never has."""
    fake = struct.pack("<Q", 0x184D2204) + lz4_block.compress(b"x", store_size=True)
    assert fake[:4] == LZ4_FRAME_MAGIC
    assert not compress_mod._is_legacy_payload(fake, CompAlgo.LZ4)
    with pytest.raises(MslParseError, match="mismatch"):
        decompress(fake, CompAlgo.LZ4)


def test_writer_guard_refuses_ambiguous_payload(monkeypatch):
    monkeypatch.setattr(compress_mod, "_is_legacy_payload", lambda p, a: True)
    with pytest.raises(MslParseError, match="ambiguous"):
        compress(b"\x00" * 64, CompAlgo.ZSTD)


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_legacy_writer_file_reads_region_bytes(tmp_path, monkeypatch, algo):
    """A file written by the old MemDiver writer (bare codec payloads)."""
    import memdiver.msl.writer as writer_mod
    monkeypatch.setattr(writer_mod, "compress", _legacy_compress)
    data = _sample(2 * 4096)
    out = tmp_path / "legacy.msl"
    w = MslWriter(out)
    w.add_memory_region(0x4000, data, compression=algo)
    w.add_end_of_capture()
    w.write()
    monkeypatch.undo()
    _assert_single_region(out, 0x4000, data, algo)


@pytest.mark.parametrize("algo", ["zstd", "lz4"])
def test_legacy_fixture_reads(tmp_path, algo):
    from tests.fixtures.generate_msl_fixtures import write_compressed_msl_fixture
    path = write_compressed_msl_fixture(tmp_path / "l.msl", algo=algo, legacy=True)
    with MslReader(path) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        assert len(_region_bytes(reader, regions[0])) == 4096


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_new_writer_file_reads_region_bytes(tmp_path, algo):
    data = _sample(3 * 4096)
    out = tmp_path / "new.msl"
    w = MslWriter(out)
    w.add_memory_region(0x8000, data, compression=algo)
    w.add_end_of_capture()
    w.write()
    _assert_single_region(out, 0x8000, data, algo)
    with MslReader(out) as reader:
        hdr = reader.collect_regions()[0].block_header
        raw = reader.read_bytes(hdr.payload_offset, hdr.payload_length)
        assert struct.unpack_from("<Q", raw)[0] == len(reader.read_block_payload(hdr))


def _assert_single_region(path, base, data, algo):
    from memdiver.msl.integrity import verify_chain
    with MslReader(path) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        region = regions[0]
        assert region.block_header.comp_algo == algo
        assert region.base_addr == base
        assert _region_bytes(reader, region) == data
        assert verify_chain(reader).valid


# ---------------------------------------------------------------- memslicer


@pytest.fixture
def memslicer():
    if not (MEMSLICER_SRC / "memslicer" / "msl" / "writer.py").exists():
        pytest.skip(f"memslicer source tree not found at {MEMSLICER_SRC}")
    sys.path.insert(0, str(MEMSLICER_SRC))
    try:
        from memslicer.msl import constants, iterator, types, writer
    except ImportError as exc:
        pytest.skip(f"memslicer not importable: {exc}")
    finally:
        sys.path.remove(str(MEMSLICER_SRC))
    return constants, types, writer, iterator


def _memslicer_file(memslicer, tmp_path, algo, pages):
    constants, types, writer, _ = memslicer
    data = _sample(pages * 4096)
    buf = io.BytesIO()
    w = writer.MSLWriter(buf, types.FileHeader(), constants.CompAlgo(int(algo)))
    w.write_memory_region(types.MemoryRegion(
        base_addr=0x10000, region_size=len(data), protection=3,
        region_type=constants.RegionType.Heap,
        page_states=[constants.PageState.CAPTURED] * pages,
        page_data_chunks=[data]))
    w.finalize()
    path = tmp_path / f"memslicer_{algo.name}_{pages}.msl"
    path.write_bytes(buf.getvalue())
    return path, data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
@pytest.mark.parametrize("pages", [1, 2, 5])
def test_memslicer_compressed_file_opens(memslicer, tmp_path, algo, pages):
    from memdiver.core.dump_source import open_dump
    path, data = _memslicer_file(memslicer, tmp_path, algo, pages)
    with MslReader(path) as reader:
        region = reader.collect_regions()[0]
        assert region.block_header.compressed
        assert region.block_header.comp_algo == algo
        assert region.base_addr == 0x10000
        assert _region_bytes(reader, region) == data
    with open_dump(path) as source:
        assert source.get_reader().collect_regions()[0].region_size == len(data)


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_memslicer_compressed_file_vas_view(memslicer, tmp_path, algo):
    # Was xfail: the run index served on-disk (compressed) bytes. Compressed
    # runs now resolve into the decompressed block payload.
    from memdiver.core.dump_source import open_dump
    path, data = _memslicer_file(memslicer, tmp_path, algo, 2)
    with open_dump(path) as source:
        assert source.read_all("vas") == data


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
def test_memdiver_file_readable_by_memslicer(memslicer, tmp_path, algo):
    _, _, _, iterator = memslicer
    data = _sample(2 * 4096)
    out = tmp_path / "md.msl"
    w = MslWriter(out)
    w.add_memory_region(0x8000, data, compression=algo)
    w.add_end_of_capture()
    w.write()
    with MslReader(out) as reader:
        hdr = reader.collect_regions()[0].block_header
        expected = reader.read_block_payload(hdr)
    with open(out, "rb") as fh:
        payloads = [b.payload for b in iterator.iterate_blocks(fh)
                    if b.block_type == 0x0001]
    assert payloads == [expected]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
