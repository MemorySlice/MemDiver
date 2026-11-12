"""Fast unit tests of the mount proof's parsing, compare and userspace-crypto logic.

``tools/vol3_capture/mount_proof_userspace.py`` (no Docker, no corpus). The real run is
claim C-MOUNT1 in ``tests/test_vol3plugins_corpus_gate.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "tools" / "vol3_capture"
_spec = importlib.util.spec_from_file_location("_vol3_capture_mount_proof", CAPTURE_DIR / "mount_proof_userspace.py")
mp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mp   # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(mp)

ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
Cipher, algorithms, modes = ciphers.Cipher, ciphers.algorithms, ciphers.modes

SAMPLES = """\
c453d501ddbe727a4747489d51fcd646a573bd3c530f354a53c8e65302f93006  /mnt/gt_luks2/gt_luks2_1.txt
9160a8a8e6d1aa5bba2b99296b639fb9ab81d4fe126703acfe7d44bb1f38ce41  /mnt/gt_luks2/gt_luks2_blob.bin
5105ffd48fcd47dfd465b70fb753f631970acaeb0b9ffab38773d6552b9bb03a  /mnt/gt_fscrypt/v1/gt_fscrypt_v1_1.txt
071474da32089a332dfcc718cd4a5e9b42e05fac7639d9f44623bccc4c63f0d2  /mnt/gt_fscrypt/v2/gt_fscrypt_v2_1.txt
"""
KEY64 = bytes(range(64))
LUKS1 = "gt_luks1: 0 651264 crypt aes-cbc-essiv:sha256 " + "11" * 32 + " 0 7:1 4096"
LUKS2 = ("gt_luks2: 0 98304 crypt aes-xts-plain64 :64:logon:cryptsetup:0bb2-d0 0 7:0 32768 1 "
         "sector_size:4096")
VERA = "gt_veracrypt: 0 130560 crypt aes-xts-plain64 " + KEY64.hex() + " 256 7:2 256"


# --------------------------------------------------------------------------- samples / results


def test_target_of_maps_guest_paths_to_targets():
    assert mp.target_of("/mnt/gt_luks2/gt_luks2_1.txt") == ("luks2", "gt_luks2_1.txt")
    assert mp.target_of("/mnt/gt_fscrypt/v2/x.bin") == ("fscrypt_v2", "x.bin")
    for bad in ("/srv/x.txt", "/mnt/gt_luks2", "/mnt/gt_luks2/"):
        with pytest.raises(ValueError):
            mp.target_of(bad)


def test_parse_samples_groups_by_target():
    targets = mp.parse_samples(SAMPLES)
    assert sorted(targets) == ["fscrypt_v1", "fscrypt_v2", "luks2"]
    assert targets["luks2"]["gt_luks2_blob.bin"].startswith("9160a8a8")
    with pytest.raises(ValueError):
        mp.parse_samples("nothex  /mnt/gt_luks2/a")


def test_match_by_name_and_by_content(tmp_path):
    (tmp_path / "a").write_bytes(b"alpha")
    (tmp_path / "b").write_bytes(b"tampered")
    expected = {"a": hashlib.sha256(b"alpha").hexdigest(), "b": hashlib.sha256(b"beta").hexdigest(),
                "c": hashlib.sha256(b"gamma").hexdigest()}
    assert mp.match_by_name(tmp_path, expected) == (1, ["b", "c"])
    assert mp.match_by_content([b"gamma", b"alpha", b"x"], expected) == (2, ["b"])


def test_results_round_trip_and_table(tmp_path):
    path = tmp_path / "r.jsonl"
    assert mp.load_results(path) == []
    mp.append_result(path, mp.Result("luks1", "dmsetup", 4, 4, "note"))
    mp.append_result(path, mp.Result("luks2", "userspace-dm", 3, 4, "", ["x"]))
    results = mp.load_results(path)
    assert [r.ok for r in results] == [True, False]
    assert not mp.Result("t", "m", 0, 0).ok
    table = mp.render_table(results).splitlines()
    assert table[0].split() == ["target", "method", "files", "result", "note"]
    assert table[1].split()[:4] == ["luks1", "dmsetup", "4/4", "MATCH"]
    assert table[2].split()[:4] == ["luks2", "userspace-dm", "3/4", "FAIL"]


def test_cli_hashcheck_and_table_exit_codes(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "f.txt").write_bytes(b"data")
    samples = tmp_path / "samples.sha256"
    samples.write_text("%s  /mnt/gt_t1/f.txt\n" % hashlib.sha256(b"data").hexdigest())
    results = tmp_path / "r.jsonl"
    argv = ["hashcheck", "--samples", str(samples), "--results", str(results), "--target", "t1",
            "--method", "m", "--root", str(root), "--note=--export dmsetup"]
    assert mp.main(argv) == 0
    assert mp.load_results(results)[0].note == "--export dmsetup"
    assert mp.main(["table", "--results", str(results)]) == 0
    (root / "f.txt").write_bytes(b"other")
    assert mp.main(argv) == 1
    assert mp.main(["table", "--results", str(results)]) == 1
    with pytest.raises(SystemExit):
        mp.main(argv[:6] + ["nope"] + argv[7:])


# --------------------------------------------------------------------------- dm tables


def test_parse_dmsetup_lines_of_all_three_volume_kinds():
    tables = mp.parse_dmsetup_export("\n".join([LUKS1, LUKS2, VERA]) + "\n")
    luks1, luks2, vera = tables["gt_luks1"], tables["gt_luks2"], tables["gt_veracrypt"]
    assert (luks1.cipher, luks1.offset, luks1.sector_size, luks1.keyring_ref) == (
        "aes-cbc-essiv:sha256", 4096, 512, ())
    assert luks2.sector_size == 4096 and luks2.options == ["sector_size:4096"]
    assert luks2.keyring_ref == (64, "logon", "cryptsetup:0bb2-d0")
    assert (vera.iv_offset, vera.device, vera.offset, vera.length) == (256, "7:2", 256, 130560)


def test_table_line_replaces_only_the_device():
    for text in (LUKS1, LUKS2, VERA):
        table = mp.parse_dmsetup_line(text)
        assert table.line() == text.split(": ", 1)[1]
        assert table.line("253:7") == text.split(": ", 1)[1].replace(" %s " % table.device, " 253:7 ")


def test_parse_dmsetup_rejects_non_crypt_and_truncated_options():
    with pytest.raises(ValueError):
        mp.parse_dmsetup_line("x: 0 10 linear 7:0 0")
    with pytest.raises(ValueError):
        mp.parse_dmsetup_line("x: 0 8 crypt aes-xts-plain64 00 0 7:0 0 2 sector_size:4096")
    assert mp.parse_dmsetup_line("0 8 crypt aes-xts-plain64 00 0 7:0 0").name == ""


def _xts(key, sector, data):
    tweak = struct.pack("<Q", sector) + bytes(8)
    return Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor().update(data)


def _essiv(key, sector, data):
    salt = hashlib.sha256(key).digest()
    iv = Cipher(algorithms.AES(salt), modes.ECB()).encryptor().update(struct.pack("<Q", sector) + bytes(8))
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)


@pytest.mark.parametrize("cipher,key,unit,options,encrypt", [
    ("aes-xts-plain64", KEY64, 512, [], _xts),
    ("aes-xts-plain64", KEY64, 4096, ["sector_size:4096"], _xts),
    ("aes-cbc-essiv:sha256", bytes(range(32)), 512, [], _essiv),
])
def test_decrypt_dm_image_round_trip(tmp_path, cipher, key, unit, options, encrypt):
    offset, iv_offset, units = 8, 256, 4
    plain = [bytes([i + 1]) * unit for i in range(units)]
    image = bytearray(offset * mp.SECTOR)
    for i, block in enumerate(plain):
        sector = iv_offset + i * unit // mp.SECTOR
        image += bytes(unit) if i == 2 else encrypt(key, sector, block)   # unit 2 never written
    (tmp_path / "img").write_bytes(bytes(image))
    table = mp.DmTable("t", 0, units * unit // mp.SECTOR, cipher, key.hex(), iv_offset, "7:0",
                       offset, options)
    assert mp.decrypt_dm_image(tmp_path / "img", table, key, tmp_path / "out") == units - 1
    out = (tmp_path / "out").read_bytes()
    assert [out[i * unit:(i + 1) * unit] for i in range(units)] == [plain[0], plain[1], bytes(unit), plain[3]]


def test_dm_decryptor_rejects_unknown_cipher_and_large_sectors(tmp_path):
    with pytest.raises(ValueError):
        mp.dm_sector_decryptor("serpent-xts-plain64", KEY64)
    table = mp.DmTable("t", 0, 8, "aes-xts-plain64", "", 0, "7:0", 0, ["iv_large_sectors"])
    with pytest.raises(ValueError):
        mp.decrypt_dm_image(tmp_path / "missing", table, KEY64, tmp_path / "out")


def test_extract_fs_refuses_unsupported_filesystems(tmp_path):
    with pytest.raises(ValueError):
        mp.extract_fs(tmp_path / "img", "xfs", tmp_path / "out")


# --------------------------------------------------------------------------- eCryptfs


def _ecryptfs_lower(plain: bytes, fek: bytes, extent: int = 4096, header_extents: int = 2) -> bytes:
    header = struct.pack(">Q", len(plain)) + bytes(12) + struct.pack(">IH", extent, header_extents)
    lower = header.ljust(extent * header_extents, b"\0")
    root_iv = hashlib.md5(fek).digest()
    padded = plain.ljust(-(-len(plain) // extent) * extent, b"\0")
    for n in range(len(padded) // extent):
        iv = hashlib.md5(root_iv + str(n).encode().ljust(16, b"\0")).digest()
        lower += Cipher(algorithms.AES(fek), modes.CBC(iv)).encryptor().update(padded[n * extent:(n + 1) * extent])
    return lower


def test_ecryptfs_header_and_iv():
    lower = _ecryptfs_lower(b"x" * 38, bytes(32))
    assert mp.ecryptfs_header(lower) == (38, 4096, 8192)
    assert mp.ecryptfs_extent_iv(b"\1" * 16, 12) == hashlib.md5(b"\1" * 16 + b"12" + bytes(14)).digest()
    with pytest.raises(ValueError):
        mp.ecryptfs_header(b"short")


@pytest.mark.parametrize("size", [1, 38, 4096, 4097, 65536])
def test_ecryptfs_decrypt_round_trip(size):
    fek = hashlib.sha256(b"fek").digest()
    plain = hashlib.sha256(b"p").digest() * (size // 32 + 1)
    assert mp.ecryptfs_decrypt(_ecryptfs_lower(plain[:size], fek), fek) == plain[:size]


def test_parse_fek_csv_keys_by_lower_file_name():
    text = ("lower_path,inode,cipher,fek_hex\n"
            "/var/lib/memdiver-gt/ecryptfs_lower/a.txt,10,aes,%s\n" % ("ab" * 32))
    assert mp.parse_fek_csv(text) == {"a.txt": b"\xab" * 32}


# --------------------------------------------------------------------------- fscrypt v2


@pytest.mark.parametrize("message", [b"", b"abc", b"x" * 111, b"x" * 112, b"y" * 300])
def test_sha512_resume_from_iv_equals_hashlib(message):
    assert mp.sha512_resume(mp.SHA512_IV, 0, message) == hashlib.sha512(message).digest()


def _midstates(prk: bytes) -> tuple:
    block = prk.ljust(128, b"\0")
    return (mp.sha512_compress(mp.SHA512_IV, bytes(b ^ 0x36 for b in block)),
            mp.sha512_compress(mp.SHA512_IV, bytes(b ^ 0x5C for b in block)))


def test_hmac_from_midstates_equals_hmac_and_hkdf_expand():
    prk = hmac.new(bytes(64), b"master key", hashlib.sha512).digest()
    ipad, opad = _midstates(prk)
    assert mp.hmac_sha512_midstates(ipad, opad, b"msg") == hmac.new(prk, b"msg", hashlib.sha512).digest()
    nonce = bytes(range(16))
    expected = hmac.new(prk, b"fscrypt\0\x02" + nonce + b"\x01", hashlib.sha512).digest()
    assert mp.fscrypt_v2_file_key(ipad, opad, nonce) == expected
    with pytest.raises(ValueError):
        mp.fscrypt_v2_file_key(ipad, opad, nonce, 65)


def test_parse_midstate_is_eight_big_endian_words():
    words = mp.parse_midstate(struct.pack(">8Q", *range(1, 9)).hex())
    assert words == list(range(1, 9))
    with pytest.raises(ValueError):
        mp.parse_midstate("00" * 63)


def test_parse_fscrypt_context_real_v1_and_v2_xattrs():
    v2 = bytes.fromhex("0201040200000000" "42c4c6ac5023e9d16eb14c7c30583868"
                       "41356fa91f8261f5d1c8c763c64d9da0")
    v1 = bytes.fromhex("01010402" "048f521e7967862f" "d34fb86d210d0b6e41878abb78484c99")
    ctx2, ctx1 = mp.parse_fscrypt_context(v2), mp.parse_fscrypt_context(v1)
    assert (ctx2["version"], ctx2["contents"], ctx2["filenames"], ctx2["key_ref"]) == (
        2, 1, 4, "42c4c6ac5023e9d16eb14c7c30583868")
    assert ctx2["nonce"] == v2[24:]
    assert (ctx1["version"], ctx1["key_ref"], ctx1["nonce"]) == (1, "048f521e7967862f", v1[12:])
    with pytest.raises(ValueError):
        mp.parse_fscrypt_context(b"\x02" * 28)


def test_fscrypt_xts_uses_the_logical_block_number_as_tweak():
    key, blocks = KEY64, [bytes([7]) * 4096, bytes([9]) * 4096]
    cipher = [_xts(key, lblk, data) for lblk, data in enumerate(blocks)]
    assert mp.fscrypt_xts_decrypt(key, cipher, 4096) == b"".join(blocks)


def test_parse_debugfs_ls_and_blocks():
    ls = """
     17   40755 (2)      0      0    4096 12-Nov-2026 10:29 .
     18  100644 (1)      0      0      40 12-Nov-2026 10:29 <encrypted (32)>
     21  100644 (1)      0      0   65536 12-Nov-2026 10:29 <encrypted (32)>
"""
    assert mp.parse_debugfs_ls(ls) == [(18, "100644", 40), (21, "100644", 65536)]
    assert mp.parse_debugfs_blocks("6192 6193 6194\n") == [6192, 6193, 6194]


# --------------------------------------------------------------------------- kernel / plugin glue


def _iowr(nr: int, size: int) -> int:
    return (3 << 30) | (size << 16) | (ord("f") << 8) | nr


def test_fscrypt_ioctl_numbers_and_add_key_layout():
    assert mp.FS_IOC_ADD_ENCRYPTION_KEY == _iowr(23, 80)
    assert mp.FS_IOC_REMOVE_ENCRYPTION_KEY == _iowr(24, 64)
    arg = mp.fscrypt_add_key_arg("048f521e7967862f", b"\x55" * 64)
    assert len(arg) == 80 + 64
    assert struct.unpack_from("<II", arg) == (mp.FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR, 0)
    assert arg[8:16].hex() == "048f521e7967862f" and arg[16:40] == bytes(24)
    assert struct.unpack_from("<II", arg, 40) == (64, 0) and arg[80:] == b"\x55" * 64
    with pytest.raises(ValueError):
        mp.fscrypt_v1_key_spec("00")


def test_proven_key_and_daemon_pid():
    rows = [{"KeyHex": "aa", "Proven": "oracle:gocryptfs-gcm"},
            {"KeyHex": "aa", "Proven": "oracle:gocryptfs-gcm"},
            {"KeyHex": "bb", "Proven": "rejected"}]
    assert mp.proven_key(rows) == "aa"
    assert mp.proven_key(rows[2:]) == ""
    with pytest.raises(ValueError):
        mp.proven_key(rows + [{"KeyHex": "cc", "Proven": "oracle:x"}])
    ps = ("UID PID PPID C STIME TTY TIME CMD\n"
          "root 9921 9908 0 10:29 ? 00:00:00 logger -t gocryptfs-9908-logger\n"
          "root 9908 1 0 10:29 ? 00:00:01 /usr/bin/gocryptfs -fg -passfile p c m\n")
    assert mp.daemon_pid(ps, "/usr/bin/gocryptfs") == 9908
    with pytest.raises(ValueError):
        mp.daemon_pid(ps, "/usr/bin/sshd")


def test_cli_dm_line_proven_key_and_daemon_pid(tmp_path, capsys):
    export = tmp_path / "dmcrypt.dmsetup.txt"
    export.write_text("\n".join([LUKS1, LUKS2, VERA]) + "\n")
    assert mp.main(["dm-line", "--dmsetup", str(export), "--name", "gt_veracrypt", "--device", "7:9"]) == 0
    assert mp.main(["dm-line", "--dmsetup", str(export), "--name", "gt_luks2", "--keyref"]) == 0
    assert mp.main(["dm-line", "--dmsetup", str(export), "--name", "gt_luks1", "--keyref"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].endswith(" 256 7:9 256") and out[1] == "logon cryptsetup:0bb2-d0" and out[2] == ""
    rows = tmp_path / "rows.json"
    rows.write_text(json.dumps([{"KeyHex": "ab", "Proven": "rejected"}]))
    assert mp.main(["proven-key", "--rows", str(rows)]) == 1


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
@pytest.mark.parametrize("script", ["mount_proof.sh", "mount_proof/kernel_proof.sh"])
def test_shell_scripts_parse(script):
    subprocess.run(["bash", "-n", str(CAPTURE_DIR / script)], check=True)
