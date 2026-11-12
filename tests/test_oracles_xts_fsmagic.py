"""The ``xts-fsmagic`` format oracle: a dm-crypt / VeraCrypt key proven by its filesystem head.

Plaintexts are the real mkfs heads in tests/fixtures/fsmagic/, encrypted here exactly as
dm-crypt lays them out (``aes`` primitive). The inline tests run the oracle the way a
generated plugin does: a fresh ``python -I`` with memdiver and both crypto libraries blocked.
"""

import ast
import base64
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.oracles import get_format, missing_contract
from memdiver.oracles.embed import BUNDLE_SOURCES_NAME, inline_source, render_bundle
from memdiver.vol3plugins.linux.secrets import aes

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fsmagic"
X = get_format("xts-fsmagic")
KEY64 = bytes(range(1, 65))
KEY32 = bytes(range(100, 132))
POISON_ALL = (
    "import sys\n"
    'for _blocked in ("memdiver", "cryptography", "Crypto"):\n'
    "    sys.modules[_blocked] = None\n"
)


def _head(name):
    return (FIXTURES / ("%s.head4k.bin" % name)).read_bytes()


def _encrypt(key, plaintext, spec="aes-xts-plain64", sector_size=512, iv_offset=0,
             iv_large=False, base=0):
    """dm-crypt encryption of ``plaintext`` placed at data-area offset ``base``."""
    out = []
    for at in range(0, len(plaintext), sector_size):
        unit = plaintext[at:at + sector_size]
        iv = aes.dm_iv_sector((base + at) // 512, iv_offset, sector_size, iv_large)
        if spec.startswith("aes-xts"):
            out.append(aes.xts_encrypt(key, iv & ((1 << 32) - 1) if spec.endswith("-plain") else iv,
                                       unit, sector_size=len(unit)))
        elif spec == "aes-cbc-essiv:sha256":
            out.append(aes.cbc_encrypt(key, aes.essiv_iv(key, iv), unit))
        else:
            fmt = "<I" if spec.endswith("-plain") else "<Q"
            iv_bytes = struct.pack(fmt, iv & ((1 << (8 * struct.calcsize(fmt))) - 1))
            out.append(aes.cbc_encrypt(key, iv_bytes + bytes(16 - len(iv_bytes)), unit))
    return b"".join(out)


def _oracle(sample, **params):
    return X.build_oracle(params, sample)


# ------------------------------------------------------------------ contract


def test_registered_and_complete():
    assert missing_contract(X) == []
    assert X.KIND == "xts-fsmagic"
    assert X.CANDIDATE_LENGTHS == (16, 24, 32, 48, 64)
    assert X.REQUIRES_PRIMITIVES == ("aes", "fsmagic")
    assert X.COST_US > 0


def test_source_is_python38_syntax():
    ast.parse(Path(X.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))


def test_built_oracle_attributes():
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4"))
    assert o.unique is True
    assert o.candidate_lengths == (32, 64)
    assert o.cost_us == X.COST_US
    assert _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")))).cost_us == X.UNKNOWN_FS_COST_US
    cbc = _oracle(X.make_sample(_encrypt(KEY32, _head("xfs_v5"), "aes-cbc-essiv:sha256"),
                                spec="aes-cbc-essiv:sha256"))
    assert cbc.candidate_lengths == (16, 24, 32)


# ------------------------------------------------------------------ proofs


@pytest.mark.parametrize(("name", "fs", "spec", "sector_size", "iv_large", "iv_offset", "key"), [
    ("ext4_csum", "ext4", "aes-xts-plain64", 4096, False, 0, KEY64),
    ("ext4_csum", "ext4", "aes-xts-plain64", 4096, True, 8, KEY64),
    ("xfs_v5", "xfs", "aes-cbc-essiv:sha256", 512, False, 0, KEY32),
    ("vfat16", "vfat", "aes-xts-plain64", 512, False, 256, KEY64),
    ("ntfs", "ntfs", "aes-xts-plain", 512, False, 0, KEY32),
    ("lvm2", "lvm2", "aes-cbc-plain64", 512, False, 3, KEY32[:16]),
    ("swap", "swap", "aes-cbc-plain", 1024, False, 0, KEY32[:24]),
    ("gpt", "gpt", "aes-xts-plain64", 2048, True, 0, KEY32),
])
def test_right_key_proven_wrong_key_rejected(name, fs, spec, sector_size, iv_large, iv_offset, key):
    ct = _encrypt(key, _head(name), spec, sector_size, iv_offset, iv_large)
    sample = X.make_sample(ct, spec=spec, sector_size=sector_size, iv_offset=iv_offset,
                           iv_large=iv_large, fs=fs)
    assert len(sample) <= X.SAMPLE_MAX_BYTES
    o = _oracle(sample)
    good = o.verify(key, {})
    assert good["status"] == "proven", good
    assert good["derived"]["fs"] == fs and good["derived"]["bits"] >= 64
    assert good["derived"]["fs_mismatch"] is False
    assert o.prefilter(key) is None
    wrong = bytes([key[0] ^ 1]) + key[1:]
    assert o.verify(wrong, {})["status"] == "rejected"


def test_btrfs_unit_at_64k():
    plain = bytearray(0x10000 + 512)
    plain[:4096] = _head("btrfs")
    plain[0x10000:0x10200] = (FIXTURES / "btrfs.sb64k.bin").read_bytes()[:512]
    ct = _encrypt(KEY64, bytes(plain))
    sample = X.make_sample(ct, fs="btrfs")  # fs=btrfs implies the btrfs unit
    header, extents = X.parse_sample(sample)
    assert [e[0] for e in extents] == [0, 0x10000] and header["extents"][1] == [0x10000, 512]
    v = _oracle(sample).verify(KEY64, {})
    assert v["status"] == "proven" and v["derived"]["fs"] == "btrfs"
    with pytest.raises(ValueError, match="btrfs_unit needs"):
        X.make_sample(ct[:8192], btrfs_unit=True)


def test_unknown_fs_never_rejects_a_random_plaintext():
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum"))))
    assert o.verify(KEY64, {})["status"] == "proven"
    wrong = o.verify(bytes(64), {})
    assert wrong["status"] == "error" and wrong["detail"].startswith("unrecognized-fs-unknown")
    assert o.prefilter(os.urandom(64)) is None  # no probe rejection without a named fs


def test_structured_unrecognized_plaintext_is_error():
    text = (b"no filesystem here, just a text file. " * 120)[:4096]
    o = _oracle(X.make_sample(_encrypt(KEY64, text), fs="ext4"))
    v = o.verify(KEY64, {})
    assert v["status"] == "error" and v["detail"].startswith("plaintext-structured-unrecognized")
    assert o.prefilter(KEY64) is None  # structured probe blocks are never a prefilter rejection


def test_zero_units_never_count():
    zero = _oracle(X.make_sample(bytes(4096), fs="ext4"))
    v = zero.verify(KEY64, {})
    assert v["status"] == "error" and v["detail"].startswith("no-written-units")
    assert zero.prefilter(KEY64) is None
    # ext4 superblock units written, the rest zero: still proven; zero units are counted apart
    ct = bytearray(_encrypt(KEY64, _head("ext4_csum")))
    ct[0:0x400] = bytes(0x400)
    ct[0x800:] = bytes(len(ct) - 0x800)
    o = _oracle(X.make_sample(bytes(ct), fs="ext4"))
    v = o.verify(KEY64, {})
    assert v["status"] == "proven" and v["derived"]["zero_units"] == 6 and v["derived"]["units"] == 2


def test_wrong_length_and_bad_candidates():
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4"))
    assert o.verify(KEY64[:48], {})["status"] == "rejected"
    assert "takes [32, 64]" in o.prefilter(KEY64[:16])
    assert o.verify("not bytes", {})["status"] == "error"
    assert o.prefilter(None) is None  # a prefilter never raises


def test_prefilter_rejects_most_wrong_keys_cheaply():
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4"))
    rejected = sum(o.prefilter(os.urandom(64)) is not None for _ in range(300))
    assert rejected >= 270  # ~99%: the rest only fall through to the full check
    for _ in range(50):
        assert o.verify(os.urandom(64), {})["status"] == "rejected"


def test_pure_and_accelerated_probe_paths_agree():
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4"))
    keys = [os.urandom(64) for _ in range(40)] + [KEY64]
    fast = [o.prefilter(k) for k in keys]
    o.backend = "pure-python"  # forces the single-block dm_decrypt_block path
    assert [o.prefilter(k) for k in keys] == fast and fast[-1] is None


def test_declared_fs_differs_from_found_head_is_still_a_proof_with_a_flag():
    sample = X.make_sample(_encrypt(KEY64, _head("xfs_v5")), fs="unknown")
    v = _oracle(sample, fs="vfat").verify(KEY64, {})
    # the vfat probe (0x1FE) sees no 55AA in XFS but the block is structured -> full check
    assert v["status"] == "proven" and v["derived"]["fs"] == "xfs" and v["derived"]["fs_mismatch"]


# ------------------------------------------------------------------ geometry and aliases


def test_veracrypt_alias():
    g = X.resolve_geometry(iv_mode="veracrypt")
    assert (g["spec"], g["iv_offset"], g["data_offset"]) == ("aes-xts-plain64", 256, 131072)
    assert X.resolve_geometry(iv_mode="veracrypt", data_offset=65536)["iv_offset"] == 128
    with pytest.raises(ValueError):
        X.resolve_geometry(iv_mode="veracrypt", iv_offset=5)
    with pytest.raises(ValueError):
        X.resolve_geometry(spec="aes-cbc-plain64", iv_mode="veracrypt")
    ct = _encrypt(KEY64, _head("vfat16"), iv_offset=256)
    assert _oracle(X.make_sample(ct, iv_mode="veracrypt", fs="vfat")).verify(KEY64, {})["status"] == "proven"
    # the same sample built without the alias needs it as a parameter
    plain = X.make_sample(ct, fs="vfat")
    assert _oracle(plain).verify(KEY64, {})["status"] == "rejected"
    assert _oracle(plain, iv_mode="veracrypt").verify(KEY64, {})["status"] == "proven"


def test_iv_mode_and_first_unit_aliases():
    assert X.canonical_spec("aes-xts-plain64", "plain") == "aes-xts-plain"
    assert X.canonical_spec("aes-xts-plain64", "essiv-sha256") == "aes-cbc-essiv:sha256"
    assert X.resolve_geometry(first_unit=7)["iv_offset"] == 7
    assert X.resolve_geometry(sector_size=4096, iv_large=True, first_unit=3)["iv_offset"] == 24
    with pytest.raises(ValueError):
        X.resolve_geometry(iv_offset=1, first_unit=7)
    with pytest.raises(ValueError):
        X.canonical_spec("aes-xts-plain64", "benbi")
    with pytest.raises(ValueError):
        X.canonical_spec("twofish-xts-plain64")


@pytest.mark.parametrize("bad", [
    {"sector_size": 1000}, {"sector_size": 8192}, {"iv_offset": -1}, {"iv_large": "yes"},
    {"key_bytes": 16}, {"spec": "aes-xts-essiv:sha256"},
])
def test_bad_geometry_raises(bad):
    with pytest.raises(ValueError):
        X.resolve_geometry(**bad)


def test_key_bytes_narrows_lengths():
    sample = X.make_sample(_encrypt(KEY32, _head("ext4_csum")), key_bytes=32, fs="ext4")
    o = _oracle(sample)
    assert o.candidate_lengths == (32,)
    assert o.verify(KEY32, {})["status"] == "proven"


def test_fs_aliases():
    assert X.canonical_fs("ext3") == "ext4" and X.canonical_fs(None) == "unknown"
    assert X.canonical_fs("FAT32") == "vfat"
    with pytest.raises(ValueError):
        X.canonical_fs("zfs")


# ------------------------------------------------------------------ sample blob


def test_sample_round_trip_and_cap():
    ct = _encrypt(KEY64, _head("ext4_csum"))
    sample = X.make_sample(ct + os.urandom(8192), fs="ext4", data_offset=1 << 24)
    header, extents = X.parse_sample(sample)
    assert header["fs"] == "ext4" and header["data_offset"] == 1 << 24
    assert extents == [(0, ct)]
    assert len(sample) <= 8192


@pytest.mark.parametrize("mutate", [
    lambda s: b"XXXX" + s[4:],
    lambda s: s[:4] + b"\x02" + s[5:],
    lambda s: s[:-16],
    lambda s: s[:3],
])
def test_malformed_samples_raise_valueerror(mutate):
    sample = X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4")
    with pytest.raises(ValueError):
        X.build_oracle({}, mutate(sample))


def test_make_sample_rejects_bad_input():
    with pytest.raises(ValueError):
        X.make_sample("text")
    with pytest.raises(ValueError):
        X.make_sample(b"short")
    with pytest.raises(ValueError):
        X.build_oracle("params", X.make_sample(bytes(512)))


def test_merge_contiguous_and_entropy_helpers():
    assert X._merge_contiguous([(512, b"b" * 512), (0, b"a" * 512), (2048, b"c" * 16)]) == {
        0: b"a" * 512 + b"b" * 512, 2048: b"c" * 16}
    assert X.shannon_entropy(b"") == 0.0
    assert X.shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_missing_primitives_give_error_not_exception(monkeypatch):
    o = _oracle(X.make_sample(_encrypt(KEY64, _head("ext4_csum")), fs="ext4"))
    monkeypatch.delattr(X, "aes")
    assert o.verify(KEY64, {})["status"] == "error"
    assert o.prefilter(os.urandom(64)) is None


# ------------------------------------------------------------------ inlined, stdlib only


def _run_isolated(tmp_path, text):
    script = tmp_path / "plugin_like.py"
    script.write_text(text, encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", script.name], cwd=tmp_path,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    return result.stdout.split()


def test_inlined_bundle_proves_with_no_memdiver_and_no_crypto_library(tmp_path):
    ct = _encrypt(KEY64, _head("vfat16"), iv_offset=256)
    sample = X.make_sample(ct, iv_mode="veracrypt", fs="vfat")
    driver = (
        "import base64\n"
        f'fmt = load_inlined("xts-fsmagic", {BUNDLE_SOURCES_NAME})\n'
        f'o = fmt.build_oracle({{}}, base64.b64decode("{base64.b64encode(sample).decode()}"))\n'
        f'key = bytes.fromhex("{KEY64.hex()}"); bad = bytes([key[0] ^ 1]) + key[1:]\n'
        'print(o.backend, o.verify(key, {})["status"], o.verify(bad, {})["status"], o.unique)\n'
    )
    out = _run_isolated(tmp_path, POISON_ALL + render_bundle(["xts-fsmagic"]) + driver)
    assert out == ["pure-python", "proven", "rejected", "True"]


def test_inline_source_carries_both_primitives():
    inlined = inline_source("xts-fsmagic")
    assert [p.name for p in inlined.primitives] == ["aes", "fsmagic"]
