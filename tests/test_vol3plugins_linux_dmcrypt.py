"""``linux.dmcrypt`` (``vol3plugins/linux/dmcrypt.py``) and its offset table.

Unit tests build synthetic kernel memory in a vol3 ``BufferDataLayer`` (the
``tests/test_vol3_runner.py`` pattern): a ``crypt_config`` laid out by the 6.8 offset table,
its ``dm_dev``/``block_device``/``gendisk``, the ``crypto_skcipher`` -> ``crypto_alg`` chain and
the AES contexts the arm64 ``xts-aes-ce`` / ``essiv-cbc-aes-sha256-ce`` drivers keep.  The
corpus test runs the plugin through the AArch64-capable volatility3 fork on the real
acquired-secrets capture and is skipped cleanly when either is absent.
"""

import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

from memdiver.vol3plugins.linux import dmcrypt  # noqa: E402
from memdiver.vol3plugins.linux.secrets import aes, luks  # noqa: E402
from memdiver.vol3plugins.linux.secrets import offsets as dm_offsets  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
LUKS_FIXTURES = REPO / "tests" / "fixtures" / "luks"
OFF = dm_offsets.DM_CRYPT_OFFSETS[("aarch64", "6.8.0-136-generic")]
KL = dmcrypt.KernelLayout()

KEY1 = bytes(range(0x10, 0x30))
KEY2 = bytes(range(0x80, 0xA0))


# --------------------------------------------------------------------------- synthetic memory


class Mem:
    """A little-endian LP64 address space in a bytearray (addresses start at BASE)."""

    BASE = 0x10000

    def __init__(self, size: int = 0x10000) -> None:
        self.buf = bytearray(size)
        self.cursor = 0x100

    def alloc(self, size: int, align: int = 64) -> int:
        self.cursor = (self.cursor + align - 1) & ~(align - 1)
        address = self.BASE + self.cursor
        self.cursor += size
        return address

    def put(self, address: int, data: bytes) -> None:
        start = address - self.BASE
        self.buf[start:start + len(data)] = data

    def ptr(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<Q", value))

    def u32(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<I", value))

    def u16(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<H", value))

    def u64(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<Q", value))

    def string(self, text: str) -> int:
        address = self.alloc(len(text) + 1, 8)
        self.put(address, text.encode() + b"\0")
        return address

    def reader(self) -> dmcrypt.SafeReader:
        context = contexts.Context()
        # addresses below BASE read as zeros (a NULL page stand-in)
        layer = physical.BufferDataLayer(context, "cfg", "mem", bytes(self.BASE) + bytes(self.buf))
        context.add_layer(layer)
        return dmcrypt.SafeReader(layer, 8, "little")


def make_tfm(mem: Mem, cra_name: str, driver: str, ctx: bytes, ctx_size: int = 0) -> int:
    """A crypto_alg + crypto_skcipher whose context holds ``ctx``; returns the skcipher."""
    alg = mem.alloc(384)
    mem.put(alg + KL["crypto_alg.cra_name"], cra_name.encode() + b"\0")
    mem.put(alg + KL["crypto_alg.cra_driver_name"], driver.encode() + b"\0")
    mem.u32(alg + KL["crypto_alg.cra_ctxsize"], ctx_size or len(ctx))
    skcipher = mem.alloc(KL["crypto_skcipher.base"] + KL["crypto_tfm.__crt_ctx"] + len(ctx))
    base = skcipher + KL["crypto_skcipher.base"]
    mem.ptr(base + KL["crypto_tfm.__crt_alg"], alg)
    mem.put(base + KL["crypto_tfm.__crt_ctx"], ctx)
    return skcipher


def xts_ce_ctx(key: bytes) -> bytes:
    half = len(key) // 2
    return aes.kernel_crypto_aes_ctx(key[:half]).ljust(488, b"\0") + aes.kernel_crypto_aes_ctx(key[half:])


def essiv_ce_ctx(key: bytes) -> bytes:
    return (aes.kernel_crypto_aes_ctx(key).ljust(488, b"\0")
            + aes.kernel_crypto_aes_ctx(hashlib.sha256(key).digest()) + bytes(8))


def make_crypt_config(mem: Mem, cipher: str, skciphers, key_size: int, tail: bytes = b"",
                      sector_size: int = 512, key_string: str = "", flags: int = 0,
                      offsets=OFF) -> int:
    member = offsets.crypt_config
    cfg = mem.alloc(member["key"] + key_size)
    dm_dev, bdev, disk = mem.alloc(48), mem.alloc(1008), mem.alloc(744)
    mem.put(dm_dev + KL["dm_dev.name"], b"7:0\0")
    mem.ptr(dm_dev + KL["dm_dev.bdev"], bdev)
    mem.ptr(bdev + KL["block_device.bd_disk"], disk)
    mem.put(disk + KL["gendisk.disk_name"], b"loop0\0")
    tfms = mem.alloc(8 * len(skciphers))
    for index, skcipher in enumerate(skciphers):
        mem.ptr(tfms + 8 * index, skcipher)
    mem.ptr(cfg + member["dev"], dm_dev)
    mem.u64(cfg + member["start"], 32768)
    mem.ptr(cfg + member["cipher_string"], mem.string(cipher))
    if key_string:
        mem.ptr(cfg + member["key_string"], mem.string(key_string))
    mem.u16(cfg + member["sector_size"], sector_size)
    mem.ptr(cfg + member["cipher_tfm"], tfms)
    mem.u32(cfg + member["tfms_count"], len(skciphers))
    mem.u64(cfg + member["flags"], flags)
    mem.u32(cfg + member["key_size"], key_size)
    mem.u32(cfg + member["key_parts"], 1)
    mem.put(cfg + member["key"], tail.ljust(key_size, b"\0"))
    return cfg


def xts_device(tail: bytes = b"", ctx: bytes = None, driver: str = "xts-aes-ce", **kw):
    mem = Mem()
    skcipher = make_tfm(mem, "xts(aes)", driver, xts_ce_ctx(KEY1 + KEY2) if ctx is None else ctx)
    cfg = make_crypt_config(mem, "aes-xts-plain64", [skcipher], 64, tail, **kw)
    return mem, cfg


def located(mem: Mem, cfg: int, offsets=OFF):
    reader = mem.reader()
    found, why = dmcrypt.relocate_crypt_config(reader, KL, cfg, offsets)
    return reader, found, why


# --------------------------------------------------------------------------- O1 schedule oracle


def test_prefilter_reads_the_shared_aes_sbox():
    # the S-box itself is checked against the FIPS-197 construction in test_vol3plugins_secrets_aes
    assert aes.SBOX is aes._AES_SBOX and len(aes.SBOX) == 256


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_schedule_scan_finds_a_kernel_ctx_at_any_word_offset(key_len):
    key = bytes((7 * i + 3) & 0xFF for i in range(key_len))
    buf = os.urandom(36) + aes.kernel_crypto_aes_ctx(key) + os.urandom(64)
    hits = dmcrypt.find_aes_schedules(buf, base=0x1000)
    assert [(h.key, h.address, h.full_ctx) for h in hits] == [(key, 0x1000 + 36, True)]


def test_zeroed_ctx_never_passes_o1():
    assert dmcrypt.find_aes_schedules(bytes(4096)) == []
    for key_len in (16, 24, 32):
        assert not dmcrypt.o1_ctx_matches(bytes(484), bytes(key_len))
        assert not dmcrypt.o1_enc_matches(bytes(484), bytes(key_len))


def test_zeroed_tfm_ctx_recovers_nothing_and_proves_nothing():
    mem, cfg = xts_device(ctx=bytes(1024))
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert recovery.key is None
    assert dmcrypt.DmCrypt.oracle_label(recovery, ("n/a", "", None)) == "none"


def test_wiped_ctx_with_key_tail_reports_the_tail_unverified():
    mem, cfg = xts_device(tail=KEY1 + KEY2, ctx=bytes(1024))
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.source, recovery.o1) == (KEY1 + KEY2, "crypt_config.key", "")
    verdict = dmcrypt.decide(recovery)
    assert (verdict.status, verdict.oracle, verdict.key) == ("unverified", "unverified", KEY1 + KEY2)


def test_key_enc_only_match_is_the_weaker_o1():
    ctx = bytearray(aes.kernel_crypto_aes_ctx(KEY1))
    ctx[300] ^= 1  # corrupt key_dec
    assert dmcrypt.o1_enc_matches(bytes(ctx), KEY1)
    assert not dmcrypt.o1_ctx_matches(bytes(ctx), KEY1)
    assert [h.full_ctx for h in dmcrypt.find_aes_schedules(bytes(ctx))] == [False]


def test_big_endian_schedule_words_are_normalised():
    ctx = aes.kernel_crypto_aes_ctx(KEY1, "big")
    hits = dmcrypt.find_aes_schedules(ctx, byteorder="big")
    assert [(h.key, h.full_ctx) for h in hits] == [(KEY1, True)]


# --------------------------------------------------------------------------- crypt_config locator


def test_locator_accepts_a_valid_crypt_config():
    mem, cfg = xts_device(sector_size=4096)
    _, found, why = located(mem, cfg)
    assert why == "ok"
    assert (found.dev_name, found.disk_name, found.cipher_string, found.key_size,
            found.sector_size, found.spec.crypto_api_name) == (
        "7:0", "loop0", "aes-xts-plain64", 64, 4096, "xts(aes)")


def test_locator_rejects_cra_name_that_does_not_match_the_cipher_string():
    mem = Mem()
    skcipher = make_tfm(mem, "cbc(aes)", "cbc-aes-ce", xts_ce_ctx(KEY1 + KEY2))
    cfg = make_crypt_config(mem, "aes-xts-plain64", [skcipher], 64)
    _, found, why = located(mem, cfg)
    assert found is None and "cra_name" in why


@pytest.mark.parametrize("member,value,needle", [
    ("key_size", 33, "key_size"), ("key_parts", 9, "key_parts"), ("sector_size", 700, "sector_size"),
])
def test_locator_rejects_implausible_numbers(member, value, needle):
    mem, cfg = xts_device()
    width = {"sector_size": 2}.get(member, 4)
    mem.put(cfg + OFF.crypt_config[member], value.to_bytes(width, "little"))
    _, found, why = located(mem, cfg)
    assert found is None and needle in why


def test_locator_rejects_a_bad_cipher_string_and_a_non_major_minor_dev():
    mem, cfg = xts_device()
    mem.ptr(cfg + OFF.crypt_config["cipher_string"], mem.string("NOT A CIPHER"))
    assert located(mem, cfg)[1] is None
    mem, cfg = xts_device()
    dm_dev = int.from_bytes(mem.buf[cfg - Mem.BASE:cfg - Mem.BASE + 8], "little")
    mem.put(dm_dev + KL["dm_dev.name"], b"loop0\0")
    assert "major:minor" in located(mem, cfg)[2]


def test_locator_repairs_a_uniformly_shifted_layout():
    shifted = dm_offsets.DmCryptOffsets(
        {k: (v + 16 if k != "dev" else v) for k, v in OFF.crypt_config.items()},
        OFF.flag_bits, OFF.cipher_flag_bits, "shifted")
    mem = Mem()
    skcipher = make_tfm(mem, "xts(aes)", "xts-aes-ce", xts_ce_ctx(KEY1 + KEY2))
    cfg = make_crypt_config(mem, "aes-xts-plain64", [skcipher], 64, offsets=shifted)
    _, found, why = located(mem, cfg)  # read with the UNshifted table
    assert found is not None and "shifted +16" in why


# --------------------------------------------------------------------------- key recovery


def test_xts_ce_layout_recovers_data_then_tweak_from_the_schedule():
    mem, cfg = xts_device()
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.source, recovery.o1) == (KEY1 + KEY2, "tfm-schedule", "O1:schedule")


def test_key_tail_equal_to_the_schedule_key_is_reported_as_crypt_config_key():
    mem, cfg = xts_device(tail=KEY1 + KEY2)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.source, recovery.o1) == (KEY1 + KEY2, "crypt_config.key", "O1:schedule")


def test_essiv_ce_layout_proves_the_iv_key_is_sha256_of_the_data_key():
    mem = Mem()
    skcipher = make_tfm(mem, "essiv(cbc(aes),sha256)", "essiv-cbc-aes-sha256-ce", essiv_ce_ctx(KEY1))
    cfg = make_crypt_config(mem, "aes-cbc-essiv:sha256", [skcipher], 32)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.o1) == (KEY1, "O1:schedule")
    assert "sha256(data) IV key" in recovery.detail


def test_unknown_driver_falls_back_to_a_scan_and_the_tail_fixes_xts_order():
    tweak_first = aes.kernel_crypto_aes_ctx(KEY2).ljust(496, b"\0") + aes.kernel_crypto_aes_ctx(KEY1)
    mem, cfg = xts_device(ctx=tweak_first, driver="xts-aes-mystery", tail=KEY1 + KEY2)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.order_known, recovery.o1) == (KEY1 + KEY2, True, "O1:schedule")


def test_unknown_driver_without_tail_flags_the_xts_order_as_unproven():
    tweak_first = aes.kernel_crypto_aes_ctx(KEY2).ljust(496, b"\0") + aes.kernel_crypto_aes_ctx(KEY1)
    mem, cfg = xts_device(ctx=tweak_first, driver="xts-aes-mystery")
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert recovery.key == KEY2 + KEY1 and not recovery.order_known
    verdict = dmcrypt.decide(recovery)
    assert (verdict.status, verdict.oracle) == ("unverified", "unverified:xts-order")


def test_template_transforms_are_followed_through_context_pointers():
    """Generic ``xts(aes)``: xts_tfm_ctx{child, tweak} points at two inner transforms."""
    mem = Mem()
    child = make_tfm(mem, "ecb(aes)", "ecb(aes-generic)", aes.kernel_crypto_aes_ctx(KEY1))
    tweak = make_tfm(mem, "aes", "aes-generic", aes.kernel_crypto_aes_ctx(KEY2))
    outer = make_tfm(mem, "xts(aes)", "xts(ecb(aes-generic))",
                     struct.pack("<QQ", child, tweak + KL["crypto_skcipher.base"]), ctx_size=16)
    cfg = make_crypt_config(mem, "aes-xts-plain64", [outer], 64)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.o1) == (KEY1 + KEY2, "O1:schedule")


# --------------------------------------------------------------------------- dmsetup line


def test_dmsetup_line_for_a_keyring_luks2_device_matches_dmsetup():
    mem, cfg = xts_device(sector_size=4096, key_string="logon:cryptsetup:c82aef61-d0" + "f5-x-d0")
    _, found, _ = located(mem, cfg)
    line = dmcrypt.dmsetup_line(0, 98304, found, "ab" * 64, 0, OFF)
    assert line == ("0 98304 crypt aes-xts-plain64 :64:logon:cryptsetup:c82aef61-d0f5-x-d0 "
                    "0 7:0 32768 1 sector_size:4096")


def test_dmsetup_line_with_hex_key_and_feature_flags():
    flags = 1 << OFF.flag_bits["DM_CRYPT_SAME_CPU"] | 1 << OFF.flag_bits["DM_CRYPT_NO_READ_WORKQUEUE"]
    mem, cfg = xts_device(flags=flags)
    _, found, _ = located(mem, cfg)
    line = dmcrypt.dmsetup_line(0, 8, found, (KEY1 + KEY2).hex(), 1, OFF)
    assert line == ("0 8 crypt aes-xts-plain64 %s 0 7:0 32768 3 allow_discards same_cpu_crypt "
                    "no_read_workqueue" % (KEY1 + KEY2).hex())


# --------------------------------------------------------------------------- O2 LUKS digest


def _gt(name: str) -> bytes:
    text = (LUKS_FIXTURES / ("%s.gt.txt" % name)).read_text()
    return bytes.fromhex(dict(line.split("=", 1) for line in text.splitlines()
                              if "=" in line and not line.startswith("#"))["volume_key_hex"])


def _scatter(header: bytes, json_page_gap: int = 3) -> tuple:
    """Physical memory where the LUKS2 JSON page is NOT contiguous with its binary header."""
    page = dmcrypt.PAGE
    memory = bytearray(page * 16)
    memory[page:2 * page] = header[:page]  # binary header at 0x1000
    memory[2 * page:3 * page] = os.urandom(page)  # unrelated page follows it
    json_at = (1 + json_page_gap) * page
    memory[json_at:json_at + page] = header[page:2 * page]
    hits = [(page, luks.LUKS_MAGIC), (json_at, dmcrypt.LUKS2_JSON_START)]

    def read(address, length):
        data = bytes(memory[address:address + length])
        return data if len(data) == length else None
    return read, hits


def test_luks2_json_area_is_re_paired_by_checksum_and_the_digest_proves_the_key():
    header = (LUKS_FIXTURES / "luks2-default.hdr.bin").read_bytes()
    read, hits = _scatter(header)
    index = dmcrypt.build_luks_index(read, hits)
    uuid = "CRYPT-LUKS2-4bb58e1b03604509a586dcd8e4f2e9aa-vol"
    assert dmcrypt.prove_o2(index, uuid, _gt("luks2-default"))[0] == "pass"
    assert dmcrypt.prove_o2(index, uuid, bytes(64))[0] == "fail"
    assert dmcrypt.prove_o2(index, "CRYPT-LUKS2-" + "0" * 32 + "-x", _gt("luks2-default"))[0] == "n/a"
    assert dmcrypt.prove_o2(index, "CRYPT-TCRYPT-vc", _gt("luks2-default"))[0] == "n/a"


def test_luks1_header_proves_its_key():
    header = (LUKS_FIXTURES / "luks1-essiv.hdr.bin").read_bytes()
    memory = bytes(8192) + header

    def read(address, length):
        data = memory[address:address + length]
        return data if len(data) == length else None
    index = dmcrypt.build_luks_index(read, [(8192, luks.LUKS_MAGIC)])
    verdict = dmcrypt.prove_o2(index, "CRYPT-LUKS1-e874df6dee9d4aa2a68a59c723d1b3c6-v", _gt("luks1-essiv"))
    assert verdict[0] == "pass"


def test_resident_header_copies_share_one_pbkdf2_run(monkeypatch):
    header = (LUKS_FIXTURES / "luks1-essiv.hdr.bin").read_bytes()
    memory = bytes(8192) + header + bytes(8192 - len(header) % 8192) + header  # page-cache + buffer copy
    second = 8192 + len(header) + 8192 - len(header) % 8192

    def read(address, length):
        data = memory[address:address + length]
        return data if len(data) == length else None
    index = dmcrypt.build_luks_index(read, [(8192, luks.LUKS_MAGIC), (second, luks.LUKS_MAGIC)])
    calls = []
    real = luks.verify_volume_key
    monkeypatch.setattr(luks, "verify_volume_key", lambda h, k: calls.append(k) or real(h, k))
    uuid = "CRYPT-LUKS1-e874df6dee9d4aa2a68a59c723d1b3c6-v"
    failed = dmcrypt.prove_o2(index, uuid, bytes(32))
    assert failed[0] == "fail" and failed[1].count(";") == 1  # one reason per copy, as before
    assert dmcrypt.prove_o2(index, uuid, bytes(32)) == failed  # decide()'s retry: cached
    assert dmcrypt.prove_o2(index, uuid, _gt("luks1-essiv"))[0] == "pass"
    assert len(index.for_uuid("e874df6dee9d4aa2a68a59c723d1b3c6")) == 2 and len(calls) == 2


def test_oracle_labels():
    good = dmcrypt.Recovery(KEY1, "tfm-schedule", "O1:schedule", "")
    assert dmcrypt.DmCrypt.oracle_label(good, ("pass", "", 1)) == "O1+O2:luks-digest"
    assert dmcrypt.DmCrypt.oracle_label(good, ("n/a", "", None)) == "O1:schedule"
    assert dmcrypt.DmCrypt.oracle_label(good, ("fail", "", 1)) == "rejected:luks-digest"
    weak = dmcrypt.Recovery(KEY1, "tfm-schedule", "O1:key_enc", "")
    assert dmcrypt.DmCrypt.oracle_label(weak, ("pass", "", 1)) == "O1:key_enc+O2:luks-digest"


# --------------------------------------------------------------------------- dm walk


def test_rb_walk_is_in_order_and_cycle_safe():
    mem = Mem()
    nodes = {name: mem.alloc(24) for name in "abc"}
    mem.ptr(nodes["b"] + KL["rb_node.rb_left"], nodes["a"])
    mem.ptr(nodes["b"] + KL["rb_node.rb_right"], nodes["c"])
    mem.ptr(nodes["c"] + KL["rb_node.rb_right"], nodes["b"])  # corrupt back-edge
    walked = list(dmcrypt.iter_rb_nodes(mem.reader(), KL, nodes["b"]))
    assert walked[:3] == [nodes["a"], nodes["b"], nodes["c"]] and len(walked) <= 4


def test_crypt_targets_are_filtered_by_target_type_name():
    mem = Mem()
    crypt_type, linear_type = mem.alloc(232), mem.alloc(232)
    mem.ptr(crypt_type + KL["target_type.name"], mem.string("crypt"))
    mem.ptr(linear_type + KL["target_type.name"], mem.string("linear"))
    targets = mem.alloc(2 * 80)
    for index, ttype in enumerate((linear_type, crypt_type)):
        mem.ptr(targets + 80 * index + KL["dm_target.type"], ttype)
        mem.u64(targets + 80 * index + KL["dm_target.len"], 100 + index)
        mem.ptr(targets + 80 * index + KL["dm_target.private"], 0xABC0 + index)
    table = mem.alloc(336)
    mem.u32(table + KL["dm_table.num_targets"], 2)
    mem.ptr(table + KL["dm_table.targets"], targets)
    assert list(dmcrypt.iter_crypt_targets(mem.reader(), KL, table)) == [(1, 0, 101, 0xABC1, 0)]


# --------------------------------------------------------------------------- offsets table


def test_offsets_json_accepts_sidecar_flat_and_rejects_incomplete():
    sidecar = {"btf_offsets": {"crypt_config": {"members": {
        k: {"offset": v} for k, v in OFF.crypt_config.items()}}}}
    assert dm_offsets.load_offsets_json(json.dumps(sidecar)).crypt_config == OFF.crypt_config
    flat = {"crypt_config": dict(OFF.crypt_config), "flag_bits": {"DM_CRYPT_SAME_CPU": 3}}
    assert dm_offsets.load_offsets_json(json.dumps(flat)).flag_bits == {"DM_CRYPT_SAME_CPU": 3}
    with pytest.raises(ValueError):
        dm_offsets.load_offsets_json(json.dumps({"crypt_config": {"dev": 0}}))


def test_offset_lookup_exact_nearest_and_none():
    assert dm_offsets.lookup_offsets("aarch64", "6.8.0-136-generic") is OFF
    assert dm_offsets.lookup_offsets("aarch64", "6.8.0-40-generic").crypt_config == OFF.crypt_config
    assert "x86_64" in dm_offsets.lookup_offsets("x86_64", "6.8.0-90-generic").source
    assert dm_offsets.lookup_offsets("aarch64", "5.4.0-1-generic") is None
    assert not OFF.missing()


# --------------------------------------------------------------------------- real capture (gated)

CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
STEM = "ubuntu-24.04-secrets_6.8.0-136-generic"
FORK = Path(os.environ.get("MEMDIVER_VOL3_ARM64_FORK", "") or "/nonexistent")


def test_table_entry_equals_the_capture_btf_offsets():
    sidecar = CAPTURE_DIR / (STEM + ".secrets.json")
    if not sidecar.is_file():
        pytest.skip("acquired-secrets sidecar not present")
    members = json.loads(sidecar.read_text())["btf_offsets"]["crypt_config"]["members"]
    assert {k: v["offset"] for k, v in members.items()} == OFF.crypt_config


X86_STEM = "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic"


LUKS_ORACLE = r"O1\+O2(\+O3)?:luks-digest(\+[a-z0-9-]+)?"
O3_ORACLE = r"O1\+O3:(pagecache-pair|vfat|ext4|xfs|ntfs|btrfs)"


def _run_capture(tmp_path, stem, vol_command, other_oracle=O3_ORACLE):
    """Run ``linux.dmcrypt`` on a real capture; assert keys, oracles and the dmsetup lines.

    ``other_oracle``: the label a non-LUKS (VeraCrypt) key must carry -- O3 on x86_64, where
    vol3 maps a ``struct page`` to its physical page.
    """
    symbols = tmp_path / "sym" / "linux"
    symbols.mkdir(parents=True)
    (symbols / (stem + ".json")).symlink_to(CAPTURE_DIR / (stem + ".isf.json"))
    (tmp_path / "cache").mkdir()  # private identifier cache: the shared one races with other runs
    command = vol_command + [
        "-q", "-r", "json", "-s", str(tmp_path / "sym"), "-p", str(REPO / "vol3plugins"),
        "-f", str(CAPTURE_DIR / (stem + ".lime")), "--cache-path", str(tmp_path / "cache"),
        "-o", str(tmp_path), "linux.dmcrypt", "--export", "dmsetup", "--verbose"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path), timeout=900)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = {row["Name"]: row for row in json.loads(result.stdout)}
    truth = {d["name"]: d for d in json.loads((CAPTURE_DIR / (stem + ".secrets.json")).read_text())["dmcrypt"]}
    assert set(rows) == set(truth)
    for name, device in truth.items():
        assert rows[name]["Key"] == device["volume_key_hex"], name
        assert rows[name]["Status"] == "proven", name
        expected = LUKS_ORACLE if device["type"].startswith("luks") else other_oracle
        assert re.fullmatch(expected, rows[name]["Oracle"]), (name, rows[name]["Oracle"])
    lines = (tmp_path / "dmcrypt.dmsetup.txt").read_text().splitlines()
    assert sorted(lines) == sorted("%s: %s" % (n, d["dm_table_showkeys"]) for n, d in truth.items())


def _capture_present(stem):
    return all((CAPTURE_DIR / (stem + ext)).is_file() for ext in (".lime", ".isf.json", ".secrets.json"))


def test_real_capture_through_the_arm64_fork(tmp_path):
    python = FORK / "env" / "bin" / "python"
    if not (_capture_present(STEM) and (FORK / "vol.py").is_file()):
        pytest.skip("aarch64 capture or volatility3-arm64 fork not present")
    _run_capture(tmp_path, STEM, [str(python if python.is_file() else sys.executable), str(FORK / "vol.py")],
                 other_oracle=r"O1:schedule|%s" % O3_ORACLE)  # arm64: no page -> physical mapping in vol3


def test_real_x86_capture_through_stock_vol(tmp_path):
    """Stock volatility3, no --offsets: the built-in x86_64 6.8.0-136 entry must carry it."""
    vol = Path(sys.executable).parent / "vol"
    if not (_capture_present(X86_STEM) and vol.is_file()):
        pytest.skip("x86_64 acquired-secrets capture or the stock vol entry point not present")
    _run_capture(tmp_path, X86_STEM, [str(vol)])


def test_generic_essiv_template_with_aesni_iv_cipher():
    """x86: essiv(cbc-aes-aesni,sha256-ni) -> {cbc child, "aes-aesni" IV cipher}; both are "data"
    in their own layouts, so the data key is the one whose sha256 is the other schedule."""
    mem = Mem()
    pad = bytes(8)  # AES-NI aligns its ctx up to 16 inside the raw context
    cbc = make_tfm(mem, "cbc(aes)", "__cbc-aes-aesni", pad + aes.kernel_crypto_aes_ctx(KEY1), 500)
    iv_cipher = make_tfm(mem, "aes", "aes-aesni",
                         pad + aes.kernel_crypto_aes_ctx(hashlib.sha256(KEY1).digest()), 500)
    outer = make_tfm(mem, "essiv(cbc(aes),sha256)", "essiv(cbc-aes-aesni,sha256-ni)",
                     struct.pack("<QQQ", cbc, iv_cipher + KL["crypto_skcipher.base"], 0), ctx_size=32)
    cfg = make_crypt_config(mem, "aes-cbc-essiv:sha256", [outer], 32)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert (recovery.key, recovery.o1) == (KEY1, "O1:schedule")
    assert "sha256(data) IV key" in recovery.detail


# --------------------------------------------------------------------------- review fixes

import logging  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from volatility3.framework import exceptions  # noqa: E402

DM_TYPES = ("hash_cell", "mapped_device", "dm_table", "dm_target", "target_type", "dm_dev", "rb_node")


class FakeVmlinux:
    """A kernel module object whose ISF lacks the dm types and the dm symbols (RHEL/Alma)."""

    symbol_table_name, layer_name, offset = "fake", "mem", 0

    def __init__(self, modules=()):
        self._modules = list(modules)

    def get_type(self, name):
        if name in DM_TYPES:
            raise exceptions.SymbolError(name, "fake", "no %s" % name)
        member_offsets = {k.split(".", 1)[1]: v for k, v in dmcrypt._LP64_DEFAULTS.items()
                          if k.startswith(name + ".")}
        return SimpleNamespace(relative_child_offset=lambda m: member_offsets[m], size=8,
                               members={m: (o, SimpleNamespace(size=16)) for m, o in member_offsets.items()})

    def get_symbol(self, name):
        raise exceptions.SymbolError(name, "fake", "no %s" % name)

    def object_from_symbol(self, name):
        assert name == "modules"
        return SimpleNamespace(to_list=lambda _type, _member: iter(self._modules))


class BarePlugin(dmcrypt.DmCrypt):
    """The plugin without a vol3 context: ``config`` becomes a plain attribute."""

    config = None
    open = None


def _plugin(vmlinux, dm_core=None):
    plugin = object.__new__(BarePlugin)
    plugin.vmlinux = vmlinux
    plugin.kl = dmcrypt.KernelLayout.from_module(vmlinux, dm_core)
    plugin.reader = Mem().reader()
    return plugin


def test_1c_layout_records_where_each_offset_came_from():
    layout = dmcrypt.KernelLayout.from_module(FakeVmlinux())
    assert layout.sources["crypto_tfm.__crt_ctx"] == "isf"
    assert "hash_cell.md" in layout.missing_walk() and "dm_dev.name" in layout.key_path_defaulted()
    with_table = dmcrypt.KernelLayout.from_module(FakeVmlinux(), OFF.dm_core)
    assert with_table.sources["hash_cell.md"] == "table" and not with_table.missing_walk()
    assert with_table.sizes["dm_target"] == 80 and not with_table.key_path_defaulted()


def test_1a_no_dm_symbols_anywhere_warns_instead_of_reporting_silence(caplog):
    with caplog.at_level(logging.WARNING):
        assert _plugin(FakeVmlinux())._devices() == []
    assert "device-mapper walk impossible" in caplog.text and "dm_mod" in caplog.text


def test_1b_roots_come_from_the_dm_mod_module_and_missing_types_are_named(caplog):
    dm_mod = SimpleNamespace(get_name=lambda: "dm_mod",
                             get_symbol=lambda n: {"name_rb_tree": 0xAB00, "_minor_idr": 0xCD00}.get(n))
    other = SimpleNamespace(get_name=lambda: "xfs", get_symbol=lambda n: None)
    plugin = _plugin(FakeVmlinux([other, dm_mod]))
    assert plugin._walk_roots() == (0xAB00, 0xCD00, "module dm_mod (kallsyms: name_rb_tree, _minor_idr)")
    with caplog.at_level(logging.WARNING):
        assert plugin._devices() == []
    assert "module dm_mod" in caplog.text and "hash_cell.md" in caplog.text and "dm_core" in caplog.text


def test_1b_module_roots_with_dm_core_offsets_walk_the_tree():
    mem = Mem()
    root, cell, md, table = mem.alloc(8), mem.alloc(88), mem.alloc(768), mem.alloc(336)
    mem.ptr(root, cell)  # name_node at offset 0 of hash_cell
    mem.ptr(cell + 56, mem.string("cryptroot"))
    mem.ptr(cell + 72, md)
    mem.ptr(md + 80, table)
    dm_mod = SimpleNamespace(get_name=lambda: "dm_mod", get_symbol=lambda n: root if n == "name_rb_tree" else None)
    plugin = _plugin(FakeVmlinux([dm_mod]), OFF.dm_core)
    plugin.reader = mem.reader()
    assert [(d.name, d.table) for d in plugin._devices()] == [("cryptroot", table)]


def test_1c_guessed_key_path_offsets_never_yield_proven():
    good = dmcrypt.Recovery(KEY1, "tfm-schedule", "O1:schedule", "")
    verdict = dmcrypt.decide(good, None, ["crypto_tfm.__crt_ctx"])
    assert (verdict.status, verdict.oracle) == ("unverified", "unverified:defaulted-offsets")


def _o2_for(good_key):
    return lambda key: ("pass", "ok", 1) if key == good_key else ("fail", "digest mismatch", 1)


def test_2_contradicting_tail_demotes_to_conflict_unless_o2_settles_it():
    mem, cfg = xts_device(tail=bytes(range(64)))
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert recovery.conflict and recovery.key == KEY1 + KEY2
    assert dmcrypt.decide(recovery).status == "conflict"
    settled = dmcrypt.decide(recovery, _o2_for(KEY1 + KEY2))
    assert (settled.status, settled.oracle) == ("proven", "O1+O2:luks-digest")
    tail_wins = dmcrypt.decide(recovery, _o2_for(bytes(range(64))))
    assert (tail_wins.status, tail_wins.key, tail_wins.source) == ("proven", bytes(range(64)), "crypt_config.key")
    assert tail_wins.oracle == "O2:luks-digest"


def test_2_tail_equal_to_swapped_halves_settles_the_order():
    tweak_first = aes.kernel_crypto_aes_ctx(KEY2).ljust(496, b"\0") + aes.kernel_crypto_aes_ctx(KEY1)
    mem, cfg = xts_device(ctx=tweak_first, driver="xts-aes-mystery", tail=KEY1 + KEY2)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert not recovery.conflict and dmcrypt.decide(recovery).status == "proven"


def test_3_pointer_chase_stays_inside_cra_ctxsize():
    mem = Mem()
    child = make_tfm(mem, "ecb(aes)", "ecb(aes-generic)", aes.kernel_crypto_aes_ctx(KEY1))
    tweak = make_tfm(mem, "aes", "aes-generic", aes.kernel_crypto_aes_ctx(KEY2))
    outer = make_tfm(mem, "xts(aes)", "xts(ecb(aes-generic))", struct.pack("<QQ", child, tweak), ctx_size=8)
    cfg = make_crypt_config(mem, "aes-xts-plain64", [outer], 64)
    reader, found, _ = located(mem, cfg)
    recovery = dmcrypt.recover_key(reader, KL, found)
    assert recovery.key is None and "found 1" in recovery.detail


def test_4_verdict_semantics():
    unordered = dmcrypt.Recovery(KEY2 + KEY1, "tfm-schedule", "O1:schedule", "", False, False,
                                 [(KEY1 + KEY2, "tfm-schedule", "O1:schedule")])
    assert dmcrypt.decide(unordered).status == "unverified"
    retried = dmcrypt.decide(unordered, _o2_for(KEY1 + KEY2))
    assert (retried.status, retried.key, retried.oracle) == ("proven", KEY1 + KEY2, "O1+O2:luks-digest")
    rejected = dmcrypt.decide(unordered, _o2_for(b"other"))
    assert (rejected.status, rejected.oracle) == ("rejected", "rejected:luks-digest")
    assert dmcrypt.decide(None).status == "none"


def test_5_offsets_accept_both_tag_size_spellings_and_require_only_read_members():
    v611 = {k: v for k, v in OFF.crypt_config.items() if k not in ("on_disk_tag_size", "iv_size",
                                                                    "key_extra_size", "key_mac_size")}
    v611["used_tag_size"] = 232
    loaded = dm_offsets.load_offsets_json(json.dumps({"crypt_config": v611}), kver="6.11.0-9-generic")
    assert loaded.tag_size_member() == "used_tag_size"
    assert loaded.flag_bits["DM_CRYPT_HIGH_PRIORITY"] == 3 and loaded.flag_bits["DM_CRYPT_NO_OFFLOAD"] == 4
    assert "DM_CRYPT_HIGH_PRIORITY" not in dm_offsets.load_offsets_json(
        json.dumps({"crypt_config": v611}), kver="6.8.0-1").flag_bits
    del v611["used_tag_size"]
    with pytest.raises(ValueError, match="used_tag_size"):
        dm_offsets.load_offsets_json(json.dumps({"crypt_config": v611}))


def test_5_unusable_offsets_file_is_a_clean_error_and_an_empty_result(tmp_path, caplog):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    for path in (bad, tmp_path / "absent.json"):
        plugin = object.__new__(BarePlugin)
        plugin.config = {"offsets": str(path)}
        plugin.kver, plugin.arch = "6.11.0", "x86_64"
        with caplog.at_level(logging.ERROR):
            assert plugin._collect() == []
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 2 and all("unusable" in r.getMessage() for r in errors)


def test_6_masterkey_export_writes_only_proven_keys_unless_asked(tmp_path):
    written = {}

    class Sink(io.BytesIO):
        def __init__(self, name):
            super().__init__()
            self.name = name

        def __exit__(self, *exc):
            written[self.name] = self.getvalue()

    records = [{"device": SimpleNamespace(name=n), "verdict": dmcrypt.Verdict(s, s, k, "x")}
               for n, s, k in (("a", "proven", KEY1), ("b", "unverified", KEY2), ("c", "none", None))]
    for unverified, expected in ((False, {"dmcrypt.a.masterkey"}),
                                 (True, {"dmcrypt.a.masterkey", "dmcrypt.b.masterkey"})):
        written.clear()
        plugin = object.__new__(BarePlugin)
        plugin.config = {"export_unverified": unverified}
        plugin.open = Sink
        plugin._export_masterkeys(records)
        assert set(written) == expected


def test_7_without_offsets_targets_still_show_cipher_and_device():
    mem, cfg = xts_device()
    probe = dmcrypt.probe_crypt_basics(mem.reader(), KL, cfg)
    assert probe == {"cipher": "aes-xts-plain64", "device": "7:0 (loop0)"}


def test_8_luks_index_parses_only_wanted_uuids_and_reads_json_pages_once():
    header = (LUKS_FIXTURES / "luks2-default.hdr.bin").read_bytes()
    read, hits = _scatter(header)
    reads = []

    def counting_read(address, length):
        reads.append((address, length))
        return read(address, length)
    hits = hits + [(hits[0][0], luks.LUKS_MAGIC)] * 5  # same header reported repeatedly
    index = dmcrypt.build_luks_index(counting_read, hits, ["4bb58e1b03604509a586dcd8e4f2e9aa"])
    assert list(index.headers) == ["4bb58e1b03604509a586dcd8e4f2e9aa"]
    json_reads = [r for r in reads if r[0] == hits[1][0]]
    assert len(json_reads) <= 2  # one contiguous + one single-page read, cached thereafter
    assert dmcrypt.build_luks_index(read, hits, ["0" * 32]).headers == {}


def test_8_pairing_budget_bounds_the_checksum_attempts():
    header = (LUKS_FIXTURES / "luks2-default.hdr.bin").read_bytes()
    read, hits = _scatter(header)
    pages = dmcrypt.JsonPages(read, [hits[1][0]], max_pairings=0)
    assert dmcrypt.parse_resident_header(read, hits[0][0], pages) is None
