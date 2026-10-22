"""Materialize of an ENCRYPTED .msl: re-encrypted copy (same key wrapping,
fresh nonce) by default, plaintext only on explicit ``decrypt_output``."""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.msl import crypto
from memdiver.msl.decoders import decode_end_of_capture
from memdiver.msl.enums import (ENC_EXT_OFFSET, FILE_HEADER_ENC_SIZE,
                                BlockType, EncAlgo, KdfType, KeyEncap,
                                TagStatus)
from memdiver.msl.hashing import hash_stream
from memdiver.msl.import_preview import preview_import
from memdiver.msl.importer import (DECRYPTED_OUTPUT_WARNING, import_dump,
                                   import_run_directory)
from memdiver.msl.integrity import verify_chain
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import parse_selection
from memdiver.msl.writer import MslEncryptionConfig

from tests.test_msl_materialize import (HEAP_STACK, _hint_vas,
                                        _regions_by_base, _writer_built_msl)

RAW_KEY = bytes(range(32))
KEPT = {0x10000000, 0x7FFF0000}  # heap + stack of _writer_built_msl
_NONCE_FIELD = slice(ENC_EXT_OFFSET + 0x10, ENC_EXT_OFFSET + 0x28)


def _kem_case(mech: KeyEncap):
    if not crypto.kem_is_available(mech):
        pytest.skip(f"{mech.name} unavailable in this environment")
    pub, priv = crypto.kem_generate_keypair(mech)
    return (MslEncryptionConfig(key_encap=mech, recipient_public=pub),
            {"kem_private_key": priv})


def _case(name: str):
    if name == "raw":
        return MslEncryptionConfig(raw_key=RAW_KEY), {"key": RAW_KEY}
    if name == "raw-xchacha":
        return (MslEncryptionConfig(enc_algo=EncAlgo.XCHACHA20_POLY1305,
                                    raw_key=RAW_KEY), {"key": RAW_KEY})
    if name == "passphrase":
        return (MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=b"pw"),
                {"passphrase": b"pw"})
    return _kem_case({"x25519": KeyEncap.X25519,
                      "mlkem768": KeyEncap.ML_KEM_768,
                      "hybrid": KeyEncap.X25519_ML_KEM_768}[name])


CASES = ["raw", "raw-xchacha", "passphrase", "x25519", "mlkem768", "hybrid"]


def _eoc_hash_ok(reader) -> bool:
    """EoC FileHash == BLAKE3(header + KEM ct + plaintext blocks before EoC)."""
    hs = reader.file_header.header_size
    kem_len = reader._enc_params.kem_ct_len if reader._enc_params else 0
    head = bytes(reader._mmap[0:hs + kem_len])
    pieces, eoc = [], None
    for hdr in reader._iter_raw_block_headers():
        start = hdr.payload_offset - (hdr.block_length - hdr.payload_length)
        if hdr.block_type == BlockType.END_OF_CAPTURE:
            eoc = decode_end_of_capture(hdr, reader.read_block_payload(hdr),
                                        reader._byte_order)
            break
        pieces.append(reader.read_bytes(start, hdr.block_length))
    return eoc is not None and eoc.file_hash == hash_stream((head, *pieces))


@pytest.mark.parametrize("name", CASES)
def test_reencrypted_copy_opens_with_same_material(tmp_path, name):
    cfg, km = _case(name)
    src = _writer_built_msl(tmp_path, encryption=cfg)
    out = tmp_path / "mat.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True,
                         key_material=km)
    assert result.materialized and result.reencrypted
    assert not result.decrypted_output
    assert DECRYPTED_OUTPUT_WARNING not in result.warnings
    src_bytes, out_bytes = src.read_bytes(), out.read_bytes()
    assert out_bytes[_NONCE_FIELD] != src_bytes[_NONCE_FIELD]  # fresh nonce
    # Same key wrapping: everything in the extension except the nonce matches.
    assert (out_bytes[ENC_EXT_OFFSET:_NONCE_FIELD.start]
            == src_bytes[ENC_EXT_OFFSET:_NONCE_FIELD.start])
    assert (out_bytes[_NONCE_FIELD.stop:FILE_HEADER_ENC_SIZE]
            == src_bytes[_NONCE_FIELD.stop:FILE_HEADER_ENC_SIZE])
    with MslReader(out) as locked:
        assert locked.tag_status is TagStatus.MISSING_KEY
    with MslReader(src, **km) as s, MslReader(out, **km) as r:
        assert r.tag_status is TagStatus.VALID
        assert r.file_header.encrypted
        assert r.file_header.dump_uuid == s.file_header.dump_uuid
        assert {g.base_addr for g in r.collect_regions()} == KEPT
        assert verify_chain(r).valid and _eoc_hash_ok(r)
    full = _regions_by_base_km(src, km)
    copy = _regions_by_base_km(out, km)
    assert copy == {b: full[b] for b in KEPT}


def _regions_by_base_km(path: Path, km: dict) -> dict:
    with MslReader(path, **km) as reader:
        return {r.base_addr: (r.region_size, [int(s) for s in r.page_states])
                for r in reader.collect_regions()}


def test_decrypt_output_writes_plaintext_with_warning(tmp_path):
    cfg, km = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    out = tmp_path / "plain.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True,
                         key_material=km, decrypt_output=True)
    assert result.decrypted_output and not result.reencrypted
    assert DECRYPTED_OUTPUT_WARNING in result.warnings
    assert result.selection_summary()["decrypted_output"] is True
    with MslReader(out) as r:
        assert r.tag_status is TagStatus.NOT_ENCRYPTED
        assert set(_regions_by_base(out)) == KEPT
        assert verify_chain(r).valid
    assert [v for v, *_ in _hint_vas(out)]  # hints remapped into the copy


@pytest.mark.parametrize("km", [{"key": b"\x02" * 32}, {"passphrase": b"x"}, {}])
def test_wrong_or_missing_key_raises_and_writes_nothing(tmp_path, km):
    cfg, _ = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    out = tmp_path / "out.msl"
    match = "decryption failed" if km.get("key") else "key material required"
    with pytest.raises(ValueError, match=match):
        import_dump(src, out, selection=HEAP_STACK, materialize=True,
                    key_material=km)
    assert not out.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_verbatim_staging_with_key_counts_regions(tmp_path):
    cfg, km = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    out = tmp_path / "copy.msl"
    result = import_dump(src, out, key_material=km, decrypt_output=True)
    assert out.read_bytes() == src.read_bytes()
    assert result.regions_written == 3
    assert any("stays encrypted" in w for w in result.warnings)


def test_verbatim_staging_with_wrong_key_warns(tmp_path):
    cfg, _ = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    result = import_dump(src, tmp_path / "copy.msl",
                         key_material={"key": b"\x09" * 32})
    assert result.regions_written == 0
    assert any("decryption failed" in w for w in result.warnings)


def test_run_directory_threads_key_material(tmp_path):
    cfg, km = _case("raw")
    run = tmp_path / "run"
    run.mkdir()
    built = _writer_built_msl(tmp_path, encryption=cfg)
    built.rename(run / "a.dump")
    (result,) = import_run_directory(run, tmp_path / "out",
                                     selection=HEAP_STACK, materialize=True,
                                     key_material=km)
    assert result.reencrypted
    with MslReader(result.output_path, **km) as r:
        assert {g.base_addr for g in r.collect_regions()} == KEPT


def test_preview_with_key_lists_regions(tmp_path):
    cfg, km = _case("passphrase")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    locked = preview_import(src).to_dict()
    assert locked["encrypted"] and not locked["decrypted"]
    assert locked["regions"] == []
    unlocked = preview_import(src, key_material=km).to_dict()
    assert unlocked["encrypted"] and unlocked["decrypted"]
    assert len(unlocked["regions"]) == 3 and not unlocked["notes"]
    wrong = preview_import(src, key_material={"passphrase": b"no"}).to_dict()
    assert not wrong["decrypted"] and "decryption failed" in wrong["notes"][0]
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    plain = preview_import(_writer_built_msl(plain_dir)).to_dict()
    assert plain["encrypted"] is False and plain["decrypted"] is False


def test_rewrap_material_redacted_and_wiped(tmp_path):
    cfg, km = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    reader = MslReader(src, **km)
    reader.open()
    material = reader._rewrap_material()
    assert RAW_KEY.hex() not in repr(material) and "redacted" in repr(material)
    assert material.cek == RAW_KEY
    assert "rewrap_material" not in repr(MslEncryptionConfig.rewrap(material))
    reader.close()
    with pytest.raises(crypto.MslCryptoError):
        material.cek  # noqa: B018 — zeroised on close
    with MslReader(src) as no_key, pytest.raises(crypto.MslCryptoError):
        no_key._rewrap_material()


def test_writer_refuses_source_nonce_and_foreign_uuid(tmp_path):
    from uuid import uuid4

    from memdiver.msl.writer import MslWriter
    cfg, km = _kem_case(KeyEncap.X25519)
    src = _writer_built_msl(tmp_path, encryption=cfg)
    with MslReader(src, **km) as reader:
        material = reader._rewrap_material()
        reuse = MslEncryptionConfig.rewrap(material)
        reuse.nonce = material.source_nonce
        w = MslWriter(tmp_path / "n.msl", dump_uuid=reader.file_header.dump_uuid,
                      encryption=reuse)
        w.add_memory_region(0, bytes(4096))
        with pytest.raises(ValueError, match="nonce"):
            w.write()
        w = MslWriter(tmp_path / "u.msl", dump_uuid=uuid4(),
                      encryption=MslEncryptionConfig.rewrap(material))
        w.add_memory_region(0, bytes(4096))
        with pytest.raises(ValueError, match="dump_uuid"):
            w.write()
    assert not (tmp_path / "n.msl").exists() and not (tmp_path / "u.msl").exists()


def test_materialize_all_selection_stays_verbatim(tmp_path):
    cfg, km = _case("raw")
    src = _writer_built_msl(tmp_path, encryption=cfg)
    out = tmp_path / "copy.msl"
    import_dump(src, out, selection=parse_selection("all"), materialize=True,
                key_material=km)
    assert out.read_bytes() == src.read_bytes()
