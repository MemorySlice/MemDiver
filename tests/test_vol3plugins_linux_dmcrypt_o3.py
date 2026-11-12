"""``linux.dmcrypt`` O3 (page-cache proof), the O3 verdict matrix and ``--export cryptsetup``.

Synthetic page caches: ``Pages`` maps ``(mapping, index)`` to a physical page and the page to
its bytes (``O3Prover`` only sees ``lookup`` / ``iterate`` / ``read``); one test drives the real
``pagecache`` XArray walk.  Ciphertext is built with ``aes.xts_encrypt`` / ``cbc_encrypt`` over
the real mkfs heads in ``tests/fixtures/fsmagic`` in the three layouts of the acquired-secrets
capture: VeraCrypt (``aes-xts-plain64``, iv_offset 256), LUKS1 (``aes-cbc-essiv:sha256``) and
LUKS2 (``aes-xts-plain64``, 4096-byte sectors without ``iv_large_sectors``).
"""

import os
import random
import shlex
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins.linux import dmcrypt  # noqa: E402
from memdiver.vol3plugins.linux.secrets import aes, luks, pagecache  # noqa: E402
from memdiver.vol3plugins.linux.secrets import offsets as dm_offsets  # noqa: E402
from tests.test_vol3plugins_linux_dmcrypt import BarePlugin, located, xts_device  # noqa: E402
from tests.test_vol3plugins_secrets_pagecache import MAPPING, Tree, page, to_phys  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fsmagic"
CIPHER_MAP, PLAIN_MAP = 0xC1000, 0xD1000
KEY64 = bytes(range(0x20, 0x60))
KEY32 = bytes(range(0x40, 0x60))
WRONG64 = bytes(range(0x60, 0xA0))


def head(name: str) -> bytes:
    return (FIXTURES / ("%s.head4k.bin" % name)).read_bytes()


def noise(size: int, seed: int) -> bytes:
    return random.Random(seed).randbytes(size)


def encrypt(key: bytes, spec: str, iv_sector: int, unit: bytes) -> bytes:
    if "-xts-" in spec:
        return aes.xts_encrypt(key, iv_sector, unit, sector_size=len(unit))
    return aes.cbc_encrypt(key, aes.essiv_iv(key, iv_sector), unit)


def encrypt_device(key: bytes, cfg, plaintext: bytes, iv_large: bool = False) -> bytes:
    size, out = cfg.sector_size, b""
    for start in range(0, len(plaintext), size):
        iv_sector = aes.dm_iv_sector(start // 512, cfg.iv_offset, size, iv_large)
        out += encrypt(key, cfg.cipher_string, iv_sector, plaintext[start:start + size])
    return out


def config(cipher="aes-xts-plain64", sector_size=512, iv_offset=0, start=256, key_size=64, tag=0):
    spec = luks.parse_cipher_spec(cipher, key_size) if cipher.startswith("aes-") else None
    return dmcrypt.CryptConfig(
        address=0, dev_name="7:0", disk_name="loop0", start=start, cipher_string=cipher, spec=spec,
        key_string=None, cipher_auth=None, iv_offset=iv_offset, sector_size=sector_size, tfms=0,
        tfms_count=1, key_size=key_size, key_parts=1, flags=0, cipher_flags=0, on_disk_tag_size=tag,
        key_tail=None, dev=0x5000)


class Pages:
    """Page caches as dicts: ``{mapping: {index: bytes}}``; physical address = a counter."""

    def __init__(self):
        self.phys, self.content, self.lookups = {}, {}, 0

    def add(self, mapping: int, index: int, data: bytes) -> None:
        phys = (len(self.content) + 1) << 12
        self.phys[(mapping, index)] = phys
        self.content[phys] = data

    def add_bytes(self, mapping: int, byte_base: int, data: bytes) -> None:
        """Place ``data`` at byte ``byte_base`` of the mapping (whole pages, zero padded)."""
        first = byte_base >> 12
        padded = bytes(byte_base & 4095) + data
        padded += bytes(-len(padded) % 4096)
        for k in range(len(padded) // 4096):
            self.add(mapping, first + k, padded[k * 4096:(k + 1) * 4096])

    def o3(self) -> dmcrypt.O3Pages:
        def lookup(mapping, index):
            self.lookups += 1
            return self.phys.get((mapping, index))

        def iterate(mapping, limit):
            found = sorted((i, p) for (m, i), p in self.phys.items() if m == mapping)
            return iter(found[:limit])

        return dmcrypt.O3Pages(lookup, iterate, self.content.get)


def prover(pages, cfg, byte_base=None, plain=PLAIN_MAP, begin=0, length=1 << 20, iv_large=False):
    byte_base = cfg.start * 512 if byte_base is None else byte_base
    return dmcrypt.O3Prover(pages.o3(), cfg, begin, length, iv_large,
                            (CIPHER_MAP, byte_base, "loop-backing"), plain)


# --------------------------------------------------------------------------- IV geometry of the real layouts


@pytest.mark.parametrize("dm_sector, iv_offset, sector_size, iv_large, expected", [
    (0, 256, 512, False, 256),  # VeraCrypt: the tweak counts from the volume header area
    (7, 256, 512, False, 263),
    (0, 0, 512, False, 0),  # LUKS1 essiv
    (8, 0, 4096, False, 8),  # LUKS2 4 KiB sectors WITHOUT iv_large_sectors: 512-byte numbering
    (8, 0, 4096, True, 1),
])
def test_iv_sector_for_the_capture_layouts(dm_sector, iv_offset, sector_size, iv_large, expected):
    assert aes.dm_iv_sector(dm_sector, iv_offset, sector_size, iv_large) == expected


LAYOUTS = [  # (name, cfg, key, fixture, fs)
    ("veracrypt", config(iv_offset=256, start=256), KEY64, "vfat16", "vfat"),
    ("luks1", config("aes-cbc-essiv:sha256", start=4096, key_size=32), KEY32, "xfs_v5", "xfs"),
    ("luks2", config(sector_size=4096, start=32768), KEY64, "ext4_csum", "ext4"),
]


@pytest.mark.parametrize("name, cfg, key, fixture, fs", LAYOUTS, ids=[x[0] for x in LAYOUTS])
def test_unit_0_decrypts_to_the_filesystem_head(name, cfg, key, fixture, fs):
    pages = Pages()
    pages.add_bytes(CIPHER_MAP, cfg.start * 512, encrypt_device(key, cfg, head(fixture)))
    o3 = prover(pages, cfg)
    verdict, detail, evidence = o3(key)
    assert (verdict, evidence) == ("pass", fs) and "unit 0 decrypts to %s" % fs in detail
    assert o3.reads == 1 and o3.units == 4096 // cfg.sector_size


def test_veracrypt_without_its_iv_offset_finds_nothing():
    cfg = config(iv_offset=256)
    pages = Pages()
    pages.add_bytes(CIPHER_MAP, cfg.start * 512, encrypt_device(KEY64, cfg, head("vfat16")))
    shifted = config(iv_offset=0)
    assert prover(pages, shifted)(KEY64) == ("n/a", "unit 0 decrypts to no known filesystem head", "")


def test_iv_large_sectors_flag_is_honoured():
    cfg = config(sector_size=4096, start=32768)
    pages = Pages()
    plaintext = noise(8192, 1)  # unit 0 has IV sector 0 either way: only the pair at unit 1 tells
    pages.add_bytes(CIPHER_MAP, cfg.start * 512, encrypt_device(KEY64, cfg, plaintext, iv_large=True))
    pages.add(PLAIN_MAP, 1, plaintext[4096:])
    assert prover(pages, cfg, iv_large=True)(KEY64)[2] == "pagecache-pair"
    assert prover(pages, cfg, iv_large=False)(KEY64)[0] == "fail"


# --------------------------------------------------------------------------- pair mode


def _paired(cfg, plaintext, resident_plain, key=KEY64, byte_base=None):
    pages = Pages()
    byte_base = cfg.start * 512 if byte_base is None else byte_base
    pages.add_bytes(CIPHER_MAP, byte_base, encrypt_device(key, cfg, plaintext))
    for index in resident_plain:
        pages.add(PLAIN_MAP, index, plaintext[index * 4096:(index + 1) * 4096])
    return pages


def test_resident_pair_proves_the_key_with_one_unit():
    cfg = config(iv_offset=256)
    plaintext = bytes(4096) + noise(4096, 2)
    o3 = prover(_paired(cfg, plaintext, [1]), cfg)
    verdict, detail, evidence = o3(KEY64)
    assert (verdict, evidence) == ("pass", "pagecache-pair") and "dm sector 8" in detail
    assert o3.units == 1


def test_wrong_key_on_a_resident_pair_fails_and_a_right_key_still_passes():
    cfg = config(iv_offset=256)
    pages = _paired(cfg, bytes(4096) + noise(4096, 3), [1])
    o3 = prover(pages, cfg)
    assert o3(WRONG64)[0] == "fail"
    assert o3(KEY64)[0] == "pass"  # the page reads are shared, the verdicts are not


def test_misaligned_backing_offset_reads_across_two_pages():
    cfg = config(iv_offset=256, start=1)  # lo_offset 0 + 512: every unit straddles two pages
    plaintext = noise(8192, 4)
    o3 = prover(_paired(cfg, plaintext, [0, 1]), cfg)
    assert o3(KEY64)[2] == "pagecache-pair"


def test_stale_plaintext_page_is_not_evidence_against_the_key():
    """A dirty dm page not yet written back decrypts (right key) to its OLD, structured bytes."""
    cfg = config(iv_offset=256)
    old = bytes(4096) + b"old metadata block".ljust(4096, b"\0")
    pages = _paired(cfg, old, [])
    pages.add(PLAIN_MAP, 1, b"new metadata block".ljust(4096, b"\0"))
    assert prover(pages, cfg)(KEY64) == ("n/a", "unit 0 decrypts to no known filesystem head", "")


def test_zero_plaintext_pages_and_target_ranges_are_skipped():
    cfg = config(iv_offset=256)
    plaintext = noise(4096, 5) + bytes(4096)
    pages = _paired(cfg, plaintext, [1])  # the resident dm page is all-zero
    assert prover(pages, cfg)(KEY64)[0] == "n/a"
    pages = _paired(cfg, plaintext, [0])
    assert prover(pages, cfg, begin=8)(KEY64)[0] == "n/a"  # page 0 lies before the target


def test_budgets_cap_page_reads_and_units():
    cfg = config(iv_offset=256)
    plaintext = noise(64 * 4096, 6)
    pages = _paired(cfg, plaintext, range(64), key=WRONG64)
    o3 = prover(pages, cfg)
    assert o3(KEY64)[0] == "fail"
    assert o3.reads <= dmcrypt.O3_MAX_PAGE_READS and o3.units <= dmcrypt.O3_MAX_UNITS
    for _ in range(10):
        o3(KEY64)
    assert o3.units <= dmcrypt.O3_MAX_UNITS and o3(KEY64) == ("n/a", "unit budget (16) spent", "")


# --------------------------------------------------------------------------- n/a never rejects


def test_nothing_resident_is_n_a_with_the_page_index():
    cfg = config(start=32768, sector_size=4096)
    o3 = prover(Pages(), cfg, byte_base=4096 * 4096 + 512 * 32768)
    assert o3(KEY64) == ("n/a", "unit 0 not resident (page idx 8192 of the loop-backing mapping)", "")


@pytest.mark.parametrize("cfg, why", [
    (config(tag=16), "integrity (AEAD) layout"),
    (config("capi:xts(aes)-plain64"), "unsupported dm-crypt cipher spec 'capi:xts(aes)-plain64'"),
])
def test_unmodelled_layouts_are_n_a(cfg, why):
    pages = Pages()
    pages.add_bytes(CIPHER_MAP, cfg.start * 512, noise(4096, 7))
    assert prover(pages, cfg)(KEY64) == ("n/a", why, "")


def test_no_source_reports_why():
    cfg = config()
    o3 = dmcrypt.O3Prover(Pages().o3(), cfg, 0, 8, False, None, None, "layout: loop_device.lo_offset")
    assert o3(KEY64) == ("n/a", "layout: loop_device.lo_offset", "")


# --------------------------------------------------------------------------- the real XArray walk


def test_prover_on_a_real_xarray_page_cache():
    cfg = config(iv_offset=256, start=0)
    tree = Tree().head(page(9))  # index 0 of MAPPING -> pfn 9
    memory = {to_phys(page(9)): encrypt_device(KEY64, cfg, head("vfat16"))}
    pages = dmcrypt.O3Pages(
        lambda mapping, index: pagecache.mapping_page(tree.reader, {}, mapping, index, to_phys),
        lambda mapping, limit: pagecache.iter_mapping_pages(tree.reader, {}, mapping, limit, to_phys),
        memory.get)
    o3 = dmcrypt.O3Prover(pages, cfg, 0, 1 << 20, False, (MAPPING, 0, "bdev"), None)
    assert o3(KEY64)[:1] + o3(KEY64)[2:] == ("pass", "vfat")


# --------------------------------------------------------------------------- sources


class FakeReader:
    pointer_size = 8

    def __init__(self):
        self.mem = {}

    def put(self, address, value, size=8):
        self.mem[address] = (value, size)

    def _get(self, address, size):
        found = self.mem.get(address)
        return found[0] if found and found[1] == size else None

    def ptr(self, address):
        return self._get(address, 8)

    def u64(self, address):
        return self._get(address, 8)

    def u32(self, address):
        return self._get(address, 4)


LAYOUT = {"dm_dev.bdev": 0, "block_device.bd_disk": 16, "block_device.bd_inode": 56, "gendisk.major": 0,
          "gendisk.private_data": 88, "gendisk.part0": 64, "loop_device.lo_backing_file": 96,
          "loop_device.lo_offset": 8, "loop_device.lo_disk": 400, "file.f_mapping": 216,
          "inode.i_mapping": 64}


def _device(major, lo_disk_ok=True, layout=LAYOUT):
    reader = FakeReader()
    dm_dev, bdev, disk, loop, backing, inode = 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xA000
    reader.put(dm_dev + layout["dm_dev.bdev"], bdev)
    reader.put(bdev + layout["block_device.bd_disk"], disk)
    reader.put(bdev + layout["block_device.bd_inode"], inode)
    reader.put(inode + layout["inode.i_mapping"], 0xB000)
    reader.put(disk + layout["gendisk.major"], major, 4)
    reader.put(disk + layout["gendisk.private_data"], loop)
    reader.put(loop + layout["loop_device.lo_disk"], disk if lo_disk_ok else 0x1234)
    reader.put(loop + layout["loop_device.lo_backing_file"], backing)
    reader.put(loop + layout["loop_device.lo_offset"], 1 << 20)
    reader.put(backing + layout["file.f_mapping"], 0xC000)
    return reader


def test_loop_device_ciphertext_is_the_backing_file_cache():
    source = dmcrypt.ciphertext_source(_device(7), LAYOUT, config(start=256))
    assert source == ((0xC000, (1 << 20) + 256 * 512, "loop-backing"), "ok")


def test_other_devices_use_their_bdev_cache_via_bd_inode_or_bd_mapping():
    assert dmcrypt.ciphertext_source(_device(8), LAYOUT, config(start=4096)) == (
        (0xB000, 4096 * 512, "bdev"), "ok")
    reader = _device(8)
    reader.put(0x6000 + 72, 0xE000)
    v610 = {k: v for k, v in LAYOUT.items() if k != "block_device.bd_inode"}
    v610["block_device.bd_mapping"] = 72
    assert dmcrypt.ciphertext_source(reader, v610, config())[0][0] == 0xE000


def test_loop_sources_that_do_not_check_out():
    assert dmcrypt.ciphertext_source(_device(7, lo_disk_ok=False), LAYOUT, config()) == (
        None, "loop_device.lo_disk does not point back to its gendisk")
    no_loop = {k: v for k, v in LAYOUT.items() if k != "loop_device.lo_offset"}
    assert dmcrypt.ciphertext_source(_device(7), no_loop, config()) == (None, "layout: loop_device.lo_offset")
    assert dmcrypt.ciphertext_source(FakeReader(), LAYOUT, config()) == (None, "backing device unreadable")


def test_plaintext_source_is_the_dm_disks_part0_cache():
    reader = FakeReader()
    reader.put(0x7000 + LAYOUT["gendisk.part0"], 0x6000)
    reader.put(0x6000 + LAYOUT["block_device.bd_inode"], 0xA000)
    reader.put(0xA000 + LAYOUT["inode.i_mapping"], 0xF000)
    device = dmcrypt.DmDevice("gt", "", "dm-0", 1, 0x7000)
    assert dmcrypt.plaintext_source(reader, LAYOUT, device) == 0xF000
    assert dmcrypt.plaintext_source(reader, LAYOUT, dmcrypt.DmDevice("gt", "", "dm-0", 1)) is None


def test_o3_layout_and_what_is_missing():
    isf = {("block_device", "bd_disk"): 16, ("gendisk", "major"): 0}
    layout = dmcrypt.o3_layout(lambda t, m: isf.get((t, m)), lambda t: 64 if t == "page" else None)
    assert layout == {"block_device.bd_disk": 16, "gendisk.major": 0, "sizeof(page)": 64}
    missing = dmcrypt.o3_missing(layout)
    assert "gendisk.part0" in missing and "dm_dev.bdev" in missing
    assert "block_device.bd_inode|bd_mapping" in missing and "sizeof(page)" not in missing
    full = dict(LAYOUT, **{k: 0 for k in dmcrypt.O3_MEMBERS}, **{"sizeof(page)": 64})
    assert dmcrypt.o3_missing(full) == []


def test_crypt_config_and_device_keep_their_pointers():
    mem, cfg = xts_device()
    _reader, found, _why = located(mem, cfg)
    assert found.dev and found.dev == struct.unpack_from("<Q", mem.buf, cfg - mem.BASE)[0]
    assert dmcrypt.DmDevice("a", "", "", 1).disk == 0


# --------------------------------------------------------------------------- decide matrix

GOOD = dmcrypt.Recovery(KEY64, "tfm-schedule", "O1:schedule", "")


def o3_for(good_key, evidence="vfat", other="fail"):
    return lambda key: ("pass", "ok", evidence) if key == good_key else (other, "x", "")


def o2_for(good_key):
    return lambda key: ("pass", "ok", 1) if key == good_key else ("fail", "digest mismatch", 1)


def test_o3_n_a_never_rejects_and_keeps_the_o1_label():
    verdict = dmcrypt.decide(GOOD, None, (), lambda key: ("n/a", "unit 0 not resident (page idx 9)", ""))
    assert (verdict.status, verdict.oracle) == ("proven", "O1:schedule")
    assert verdict.o3 == ("n/a", "unit 0 not resident (page idx 9)", "")


def test_o3_pass_without_o2_proves_with_its_evidence():
    assert dmcrypt.decide(GOOD, None, (), o3_for(KEY64)).oracle == "O1+O3:vfat"
    assert dmcrypt.decide(GOOD, None, (), o3_for(KEY64, "pagecache-pair")).oracle == "O1+O3:pagecache-pair"
    weak = dmcrypt.Recovery(KEY64, "tfm-schedule", "O1:key_enc", "")
    assert dmcrypt.decide(weak, None, (), o3_for(KEY64)).oracle == "O1:key_enc+O3:vfat"
    tail_only = dmcrypt.Recovery(KEY64, "crypt_config.key", "", "")
    assert (dmcrypt.decide(tail_only, None, (), o3_for(KEY64)).status,
            dmcrypt.decide(tail_only).status) == ("proven", "unverified")


def test_o3_settles_the_xts_half_order():
    swapped = KEY64[32:] + KEY64[:32]
    unordered = dmcrypt.Recovery(swapped, "tfm-schedule", "O1:schedule", "", False)
    assert dmcrypt.decide(unordered).oracle == "unverified:xts-order"
    settled = dmcrypt.decide(unordered, None, (), o3_for(KEY64))
    assert (settled.status, settled.key, settled.oracle) == ("proven", KEY64, "O1+O3:vfat")
    first_try = dmcrypt.decide(unordered, None, (), o3_for(swapped))
    assert (first_try.status, first_try.key) == ("proven", swapped)


def test_o3_fail_rejects_only_without_an_o2_pass():
    rejected = dmcrypt.decide(GOOD, None, (), o3_for(b"other"))
    assert (rejected.status, rejected.oracle, rejected.o3[0]) == ("rejected", "rejected:pagecache", "fail")
    kept = dmcrypt.decide(GOOD, o2_for(KEY64), (), o3_for(b"other"))
    assert (kept.status, kept.oracle, kept.o3[0]) == ("proven", "O1+O2:luks-digest", "fail")
    o2_rejects = dmcrypt.decide(GOOD, o2_for(b"other"), (), o3_for(KEY64))
    assert (o2_rejects.status, o2_rejects.oracle) == ("rejected", "rejected:luks-digest")


def test_o2_and_o3_both_pass():
    both = dmcrypt.decide(GOOD, o2_for(KEY64), (), o3_for(KEY64, "ext4"))
    assert (both.status, both.oracle) == ("proven", "O1+O2+O3:luks-digest+ext4")
    assert dmcrypt.DmCrypt.oracle_label(GOOD, ("pass", "", 1), ("pass", "", "xfs")) == "O1+O2+O3:luks-digest+xfs"
    assert dmcrypt.DmCrypt.oracle_label(GOOD, ("n/a", "", None), ("pass", "", "vfat")) == "O1+O3:vfat"
    assert dmcrypt.DmCrypt.oracle_label(GOOD, ("n/a", "", None), ("fail", "", "")) == "rejected:pagecache"


def test_o3_settles_a_conflict_and_guessed_offsets_still_demote():
    conflict = dmcrypt.Recovery(KEY64, "tfm-schedule", "O1:schedule", "", True, True,
                                [(WRONG64, "crypt_config.key", "")])
    assert dmcrypt.decide(conflict, None, (), lambda key: ("n/a", "", "")).status == "conflict"
    tail_wins = dmcrypt.decide(conflict, None, (), o3_for(WRONG64))
    assert (tail_wins.status, tail_wins.key, tail_wins.oracle) == ("proven", WRONG64, "O3:vfat")
    guarded = dmcrypt.decide(GOOD, None, ["crypto_tfm.__crt_ctx"], o3_for(KEY64))
    assert (guarded.status, guarded.oracle) == ("unverified", "unverified:defaulted-offsets")


# --------------------------------------------------------------------------- --export cryptsetup


def _sh_syntax_ok(script: str) -> bool:
    return subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0


def test_luks_script_uses_the_volume_key_file():
    cfg = config(start=32768)
    script = dmcrypt.cryptsetup_script("gt_luks2", "CRYPT-LUKS2-" + "a" * 32 + "-gt_luks2", cfg,
                                       "dmcrypt.gt_luks2.volume-key", "unused", "O1+O2:luks-digest")
    assert 'cryptsetup open --type luks2 --volume-key-file "$KEY" "$DEVICE" gt_luks2' in script
    assert "DEVICE=/dev/loop0" in script and _sh_syntax_ok(script)


def test_plain_script_carries_the_table_geometry():
    cfg = config(start=2048, iv_offset=16, sector_size=4096)
    script = dmcrypt.cryptsetup_script("p", "CRYPT-PLAIN-p", cfg, "k", "unused", "O1+O3:ext4",
                                       discards=True, iv_large=True)
    line = [x for x in script.splitlines() if x.startswith("cryptsetup")][0]
    assert line == ('cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 --hash plain '
                    '--keyfile-size 64 --offset 2048 --skip 16 --sector-size 4096 --iv-large-sectors '
                    '--allow-discards --key-file "$KEY" "$DEVICE" p')


def test_veracrypt_script_replays_the_table_and_says_why():
    replay = "0 32256 crypt aes-xts-plain64 %s 256 7:2 256" % KEY64.hex()
    script = dmcrypt.cryptsetup_script("gt_veracrypt", "", config(iv_offset=256), "k", replay, "O1+O3:vfat")
    assert "dmsetup create gt_veracrypt --table '%s'" % replay in script
    assert "--veracrypt needs the header password" in script and _sh_syntax_ok(script)


def test_hostile_names_stay_quoted(tmp_path):
    name = "x'; touch %s/pwned; '\n#" % tmp_path
    script = dmcrypt.cryptsetup_script(name, "", config(), "k$(id)", "0 1 crypt", "O1+O3:vfat")
    words = shlex.split(script, comments=True)
    assert words[words.index("create") + 1] == name
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "dmsetup").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "dmsetup").chmod(0o755)
    env = dict(os.environ, PATH="%s:%s" % (fake_bin, os.environ["PATH"]))
    subprocess.run(["sh", "-c", script], env=env, check=True)
    assert not (tmp_path / "pwned").exists()


def test_cryptsetup_export_writes_proven_targets_only():
    written = {}

    class Sink:
        def __init__(self, name):
            self.name, self.data = name, b""

        def __enter__(self):
            return self

        def write(self, data):
            self.data += data

        def __exit__(self, *exc):
            written[self.name] = self.data

    cfg = config(iv_offset=256)
    offsets = dm_offsets.DM_CRYPT_OFFSETS[("aarch64", "6.8.0-136-generic")]
    records = [{"device": SimpleNamespace(name=n, uuid=""), "cfg": cfg, "index": i, "discards": 0,
                "verdict": dmcrypt.Verdict(s, "O1+O3:vfat", k, "x"),
                "replay_line": lambda key_hex: "0 8 crypt aes-xts-plain64 %s 256 7:0 256" % key_hex}
               for n, i, s, k in (("a", 0, "proven", KEY64), ("a", 1, "proven", KEY64),
                                  ("b", 0, "unverified", KEY64), ("c", 0, "none", None))]
    plugin = object.__new__(BarePlugin)
    plugin.config, plugin.open, plugin.offsets = {}, Sink, offsets
    plugin._export_cryptsetup(records)
    assert set(written) == {"dmcrypt.a.volume-key", "dmcrypt.a.open.sh",
                            "dmcrypt.a.t1.volume-key", "dmcrypt.a.t1.open.sh"}
    assert written["dmcrypt.a.volume-key"] == KEY64
    assert KEY64.hex().encode() in written["dmcrypt.a.open.sh"]
