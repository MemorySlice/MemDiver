"""End-to-end AEAD encryption tests: writer -> reader round-trip (spec §10)."""

import os

import pytest

from msl import crypto
from msl.enums import (FILE_HEADER_ENC_SIZE, BlockType, EncAlgo, HeaderFlag,
                       KdfType, KeyEncap, NodeKind, TagStatus)
from msl.reader import MslReader
from msl.writer import MslEncryptionConfig, MslWriter
from msl.types import MslPointerGraphEdge, MslPointerGraphNode

_CIPHERS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]


def _write_encrypted(path, cfg, *, data=b"\xAB" * 4096):
    w = MslWriter(path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_key_hint(region_uuid=w.dump_uuid, offset=0, key_length=32,
                   key_type=0x0003, protocol=0x0002)  # arbitrary; just another block
    w.add_end_of_capture()
    w.write()


# -- Round-trip per cipher, raw key --

@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
def test_encrypt_rawkey_roundtrip(tmp_path, algo):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    key = os.urandom(32)
    out = tmp_path / f"raw_{algo.name}.msl"
    cfg = MslEncryptionConfig(enc_algo=algo, kdf_type=KdfType.NONE,
                              key_encap=KeyEncap.NONE, raw_key=key)
    _write_encrypted(out, cfg, data=b"\xCD" * 4096)

    # On-disk header: 128 bytes, ENCRYPTED flag set
    raw = out.read_bytes()
    assert raw[9] == FILE_HEADER_ENC_SIZE  # HeaderSize byte
    flags = int.from_bytes(raw[0x0C:0x10], "little")
    assert flags & HeaderFlag.ENCRYPTED

    with MslReader(out, key=key) as reader:
        assert reader.tag_status == TagStatus.VALID
        regions = reader.collect_regions()
        assert len(regions) == 1
        assert regions[0].base_addr == 0x1000
        # All decrypted blocks carry zero PrevHash (spec §10.6)
        for hdr, _ in reader.iter_blocks():
            assert hdr.prev_hash == b"\x00" * 32
        # EoC FileHash is computed over plaintext -> non-zero
        eoc = reader.collect_end_of_capture()
        assert len(eoc) == 1 and eoc[0].file_hash != b"\x00" * 32


def test_encrypt_passphrase_roundtrip(tmp_path):
    if not crypto.kdf_is_available(KdfType.ARGON2ID):
        pytest.skip("argon2-cffi not installed")
    out = tmp_path / "passphrase.msl"
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=b"correct horse")
    _write_encrypted(out, cfg)
    with MslReader(out, passphrase=b"correct horse") as reader:
        assert reader.tag_status == TagStatus.VALID
        assert len(reader.collect_regions()) == 1


def test_encrypt_x25519_roundtrip(tmp_path):
    if not crypto.kem_is_available(KeyEncap.X25519):
        pytest.skip("cryptography not installed")
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519)
    out = tmp_path / "x25519.msl"
    cfg = MslEncryptionConfig(key_encap=KeyEncap.X25519, recipient_public=pub)
    _write_encrypted(out, cfg)
    with MslReader(out, kem_private_key=priv) as reader:
        assert reader.tag_status == TagStatus.VALID
        assert len(reader.collect_regions()) == 1


# -- Failure modes --

def test_encrypt_wrong_key_corrupted(tmp_path):
    key = os.urandom(32)
    out = tmp_path / "wrongkey.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    with MslReader(out, key=os.urandom(32)) as reader:  # different key
        assert reader.tag_status == TagStatus.CORRUPTED
        assert list(reader.iter_blocks()) == []  # no plaintext exposed


def test_encrypt_missing_key(tmp_path):
    out = tmp_path / "nokey.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=os.urandom(32)))
    with MslReader(out) as reader:  # no key supplied
        assert reader.tag_status == TagStatus.MISSING_KEY
        assert list(reader.iter_blocks()) == []


def test_encrypt_malformed_algo_byte_no_crash(tmp_path):
    """A malformed encrypted header declaring an unknown cipher suite must
    report CORRUPTED rather than crashing open() with an uncaught ValueError
    (the EncAlgo/KeyEncap/KdfType enum coercions run on untrusted bytes)."""
    key = os.urandom(32)
    out = tmp_path / "bad_algo.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    data = bytearray(out.read_bytes())
    data[0x40] = 0x7E  # EncAlgo byte -> not a defined EncAlgo value
    out.write_bytes(bytes(data))
    with MslReader(out, key=key) as reader:  # must not raise
        assert reader.tag_status == TagStatus.CORRUPTED
        assert list(reader.iter_blocks()) == []


def test_encrypt_tampered_ciphertext_corrupted(tmp_path):
    key = os.urandom(32)
    out = tmp_path / "tampered.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    data = bytearray(out.read_bytes())
    data[FILE_HEADER_ENC_SIZE + 5] ^= 0xFF  # flip a ciphertext byte
    out.write_bytes(bytes(data))
    with MslReader(out, key=key) as reader:
        assert reader.tag_status == TagStatus.CORRUPTED


def test_encrypt_tampered_header_aad_corrupted(tmp_path):
    """The 128-byte header is AAD; mutating it must fail AEAD verification."""
    key = os.urandom(32)
    out = tmp_path / "tampered_hdr.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    data = bytearray(out.read_bytes())
    data[0x34] ^= 0xFF  # flip a PID byte inside the header (part of AAD)
    out.write_bytes(bytes(data))
    with MslReader(out, key=key) as reader:
        assert reader.tag_status == TagStatus.CORRUPTED


# -- Determinism / nonce handling --

def test_encrypt_configured_nonce_stored_in_header(tmp_path):
    """A supplied nonce is written verbatim to the 24-byte header Nonce field
    (offset 0x50). Pins the nonce plumbing the reader relies on to decrypt."""
    key = os.urandom(32)
    nonce = os.urandom(24)
    out = tmp_path / "nonce.msl"
    w = MslWriter(out, pid=7, encryption=MslEncryptionConfig(
        raw_key=key, nonce=nonce))
    w.add_memory_region(0x1000, b"\xEE" * 4096)
    w.add_end_of_capture()
    w.write()

    stored = out.read_bytes()[0x50:0x68]  # Nonce field, 24 bytes
    assert stored == nonce
    # And it still decrypts with that nonce
    with MslReader(out, key=key) as reader:
        assert reader.tag_status == TagStatus.VALID


# -- Integrity chain on encrypted files --

def test_encrypt_verify_chain_skips_prevhash(tmp_path):
    """verify_chain on an encrypted file skips PrevHash (spec §14.2.16) and
    reports valid; integrity came from the AEAD tag at open()."""
    from msl.integrity import verify_chain
    key = os.urandom(32)
    out = tmp_path / "chain.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    with MslReader(out, key=key) as reader:
        report = verify_chain(reader)
        assert report.valid
        assert report.block_count >= 2  # region + key hint + EoC


# -- Encrypted + POINTER_GRAPH appendix (inside the encrypted region) --

def test_encrypt_with_pointer_graph_appendix(tmp_path):
    """The appendix lives inside the AEAD envelope; the reader recovers it
    from the decrypted stream after EoC and does NOT leak it in plaintext."""
    key = os.urandom(32)
    out = tmp_path / "enc_pg.msl"
    nodes = [MslPointerGraphNode(node_kind=NodeKind.ADDRESS, value=0xDEAD, label="x")]
    edges = [MslPointerGraphEdge(src_idx=0, dst_idx=0, edge_kind=1, metadata="self")]
    w = MslWriter(out, pid=7, encryption=MslEncryptionConfig(raw_key=key))
    w.add_memory_region(0x1000, b"\x11" * 4096)
    w.add_pointer_graph(nodes, edges)
    w.add_end_of_capture()
    w.write()

    # The pointer-graph metadata must NOT appear in plaintext on disk
    # (it lives inside the AEAD envelope, not after the tag).
    assert b"self" not in out.read_bytes()

    with MslReader(out, key=key) as reader:
        assert reader.tag_status == TagStatus.VALID
        graphs = reader.collect_pointer_graphs()
        assert len(graphs) == 1
        assert tuple(graphs[0].nodes) == tuple(nodes)
        assert tuple(graphs[0].edges) == tuple(edges)


# -- ML-KEM / hybrid (skip-gated on liboqs-python) --

@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519_ML_KEM_768),
                    reason="hybrid requires cryptography + liboqs-python ([crypto])")
def test_encrypt_hybrid_kem_roundtrip(tmp_path):
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519_ML_KEM_768)
    out = tmp_path / "hybrid.msl"
    cfg = MslEncryptionConfig(key_encap=KeyEncap.X25519_ML_KEM_768,
                              recipient_public=pub)
    _write_encrypted(out, cfg)
    with MslReader(out, kem_private_key=priv) as reader:
        assert reader.tag_status == TagStatus.VALID
        assert len(reader.collect_regions()) == 1


# -- Integration: open_dump + CLI key plumbing --

def test_open_dump_decrypts_with_key(tmp_path):
    """open_dump forwards key material to the MslReader; the source reports
    VALID tag_status and reads decrypted regions."""
    from core.dump_source import open_dump
    key = os.urandom(32)
    out = tmp_path / "dumpsrc.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=key))
    with open_dump(out, key=key) as source:
        assert source.tag_status == TagStatus.VALID
        assert len(source.get_reader().collect_regions()) == 1


def test_open_dump_encrypted_without_key_reports_missing(tmp_path):
    from core.dump_source import open_dump
    out = tmp_path / "dumpsrc_nokey.msl"
    _write_encrypted(out, MslEncryptionConfig(raw_key=os.urandom(32)))
    with open_dump(out) as source:
        assert source.tag_status == TagStatus.MISSING_KEY


def test_cli_key_material_from_args_reads_key_file(tmp_path):
    """The CLI helper loads a raw key from --key-file and a passphrase."""
    import argparse
    from cli import _key_material_from_args
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    args = argparse.Namespace(key_file=str(keyfile), passphrase="pw", kem_key_file=None)
    km = _key_material_from_args(args)
    assert km["key"] == key
    assert km["passphrase"] == b"pw"
    assert km["kem_private_key"] is None


def test_cli_parser_accepts_decrypt_flags():
    """The brute-force and consensus subcommands accept --key-file."""
    from cli import _build_parser
    parser = _build_parser()
    ns = parser.parse_args([
        "brute-force", "--candidates", "c.json", "--dump", "d.msl",
        "--oracle", "o.py", "--output", "hits.json", "--key-file", "k.bin",
    ])
    assert ns.key_file == "k.bin"


# Every dump-reading subcommand must accept the shared decryption flags.
_DECRYPT_COMMAND_ARGV = {
    "consensus-add": ["consensus-add", "--state", "s.json", "d.msl"],
    "search-reduce": ["search-reduce", "--state", "s.json",
                      "--reference-dump", "d.msl", "--output", "o.json"],
    "n-sweep": ["n-sweep", "--runs-dir", "r", "--oracle", "o.py",
                "--output-dir", "od"],
    "emit-plugin": ["emit-plugin", "--hit", "h.json", "--reference", "d.msl",
                    "--name", "N", "--output", "o.py"],
    "export": ["export", "d1.msl", "d2.msl"],
}


@pytest.mark.parametrize("argv", list(_DECRYPT_COMMAND_ARGV.values()),
                         ids=list(_DECRYPT_COMMAND_ARGV))
def test_cli_dump_commands_accept_decrypt_flags(argv):
    """Each dump-reading subcommand wires in the decrypt parent parser."""
    from cli import _build_parser
    parser = _build_parser()
    ns = parser.parse_args(argv + ["--key-file", "k.bin",
                                   "--passphrase", "pw", "--kem-key-file", "kp.bin"])
    assert ns.key_file == "k.bin"
    assert ns.passphrase == "pw"
    assert ns.kem_key_file == "kp.bin"


def test_cli_consensus_add_decrypts_with_key(tmp_path, capsys):
    """consensus-add folds an encrypted dump when given --key-file and
    surfaces the VALID AEAD line on stderr."""
    import argparse
    from cli import _cmd_consensus_begin, _cmd_consensus_add

    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    dump = tmp_path / "enc.msl"
    _write_encrypted(dump, MslEncryptionConfig(raw_key=key))
    state = tmp_path / "session.json"

    rc = _cmd_consensus_begin(argparse.Namespace(state=str(state), size=256,
                                                 verbose=False))
    assert rc == 0
    capsys.readouterr()  # drop begin output

    rc = _cmd_consensus_add(argparse.Namespace(
        state=str(state), dump=str(dump), key_file=str(keyfile),
        passphrase=None, kem_key_file=None, verbose=False))
    assert rc == 0
    assert "AEAD verified" in capsys.readouterr().err


def test_cli_consensus_add_without_key_warns_missing(tmp_path, capsys):
    """consensus-add on an encrypted dump with no key warns MISSING_KEY."""
    import argparse
    from cli import _cmd_consensus_begin, _cmd_consensus_add

    dump = tmp_path / "enc_nokey.msl"
    _write_encrypted(dump, MslEncryptionConfig(raw_key=os.urandom(32)))
    state = tmp_path / "session.json"
    _cmd_consensus_begin(argparse.Namespace(state=str(state), size=256,
                                            verbose=False))
    capsys.readouterr()

    _cmd_consensus_add(argparse.Namespace(
        state=str(state), dump=str(dump), key_file=None,
        passphrase=None, kem_key_file=None, verbose=False))
    assert "encrypted" in capsys.readouterr().err.lower()


# -- gen-kem-key CLI --

def test_cli_gen_kem_key_x25519(tmp_path):
    """gen-kem-key writes a 32/32-byte X25519 keypair (no liboqs needed)."""
    import argparse
    from cli import _cmd_gen_kem_key
    pub, priv = tmp_path / "pub.bin", tmp_path / "priv.bin"
    rc = _cmd_gen_kem_key(argparse.Namespace(
        mechanism="X25519", public_out=str(pub), private_out=str(priv),
        verbose=False))
    assert rc == 0
    assert len(pub.read_bytes()) == 32
    assert len(priv.read_bytes()) == 32


def test_cli_gen_kem_key_parser_accepts_all_mechanisms():
    from cli import _build_parser
    parser = _build_parser()
    ns = parser.parse_args(["gen-kem-key", "--mechanism", "X25519+ML-KEM-768",
                            "--public-out", "p.bin", "--private-out", "s.bin"])
    assert ns.mechanism == "X25519+ML-KEM-768"
    assert ns.public_out == "p.bin" and ns.private_out == "s.bin"


def test_cli_gen_kem_key_unavailable_mechanism(tmp_path, capsys):
    """ML-KEM keygen without liboqs exits non-zero with an install hint."""
    if crypto.kem_is_available(KeyEncap.ML_KEM_768):
        pytest.skip("liboqs installed; unavailability path not exercised")
    import argparse
    from cli import _cmd_gen_kem_key
    rc = _cmd_gen_kem_key(argparse.Namespace(
        mechanism="ML-KEM-768", public_out=str(tmp_path / "p"),
        private_out=str(tmp_path / "s"), verbose=False))
    assert rc == 1
    assert "memdiver[crypto]" in capsys.readouterr().err


@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519_ML_KEM_768),
                    reason="hybrid requires cryptography + liboqs-python ([crypto])")
def test_cli_gen_kem_key_hybrid_roundtrip(tmp_path):
    """A hybrid keypair from gen-kem-key decrypts an encrypted dump end-to-end."""
    import argparse
    from cli import _cmd_gen_kem_key
    from core.dump_source import open_dump
    pub, priv = tmp_path / "hpub.bin", tmp_path / "hpriv.bin"
    rc = _cmd_gen_kem_key(argparse.Namespace(
        mechanism="X25519+ML-KEM-768", public_out=str(pub),
        private_out=str(priv), verbose=False))
    assert rc == 0
    assert len(pub.read_bytes()) == 32 + 1184  # X25519 || ML-KEM-768 public
    out = tmp_path / "hybrid_cli.msl"
    _write_encrypted(out, MslEncryptionConfig(
        key_encap=KeyEncap.X25519_ML_KEM_768, recipient_public=pub.read_bytes()))
    with open_dump(out, kem_private_key=priv.read_bytes()) as source:
        assert source.tag_status == TagStatus.VALID
