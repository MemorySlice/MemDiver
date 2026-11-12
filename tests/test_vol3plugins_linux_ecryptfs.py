"""``linux.ecryptfs`` (``vol3plugins/linux/ecryptfs.py``).

Unit tests: the root-IV oracle (``root_iv == MD5(key[:key_size])[:iv_bytes]``), the tfm-schedule
second proof, the never-proven rules (zero key, key_size 0, KEY_VALID unset, guessed key-path
offsets), container_of arithmetic, and a synthetic superblock -> inode -> crypt_stat walk laid out
in a vol3 ``BufferDataLayer`` at the LP64 6.8 offsets.

Corpus tests (``MEMDIVER_SECRETS_CORPUS`` = absolute path of the acquired-secrets capture dir) run
the plugin through stock ``vol`` (``MEMDIVER_VOL3_VOL``, else ``vol`` on PATH / next to this
interpreter) and, when ``MEMDIVER_VOL3_ALT_VOL_PY`` names a second ``vol.py`` (e.g. 2.28.2), through
that too, on both x86_64 captures.  Ground truth: each lower file's header is recovered from the
image's page cache (``linux.pagecache.InodePages --dump``), its tag-3 packet decrypted with the
sidecar FEKEK (AES-ECB, the passphrase-mount key wrap), and the result must equal the recovered FEK.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts, exceptions  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

from memdiver.vol3plugins.linux import dmcrypt, ecryptfs as ec, keyring  # noqa: E402
from memdiver.vol3plugins.linux.secrets import aes  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
EL = ec.EcryptfsLayout()
KL = keyring.KeyLayout()
FEK = bytes(range(1, 33))
VALID = ec.ECRYPTFS_KEY_VALID | ec.ECRYPTFS_ENCRYPTED


def crypt_stat(key: bytes = FEK, key_size: int = 32, iv_bytes: int = 16, flags: int = VALID,
               root_iv: bytes = None, tfm: int = 0) -> ec.CryptStat:
    if root_iv is None:
        root_iv = hashlib.md5(key[:key_size]).digest()[:iv_bytes]
    return ec.CryptStat(address=0x1000, flags=flags, iv_bytes=iv_bytes, key_size=key_size,
                        mount_crypt_stat=0, tfm=tfm, cipher="aes", key_area=key.ljust(64, b"\0"),
                        root_iv=root_iv.ljust(16, b"\0"))


# --------------------------------------------------------------------------- root-IV oracle


def test_root_iv_oracle_proves_the_right_fek():
    verdict = ec.decide(crypt_stat())
    assert verdict.proven == "oracle:ecryptfs-root-iv" and verdict.root_iv == "pass"


def test_root_iv_oracle_rejects_a_wrong_fek():
    other = bytes(range(2, 34))
    verdict = ec.decide(crypt_stat(root_iv=hashlib.md5(other).digest()))
    assert verdict.proven == "rejected" and verdict.root_iv == "fail"


def test_root_iv_covers_only_key_size():
    key = FEK + bytes(range(100, 132))  # tail beyond key_size must not enter the hash
    cs = crypt_stat(key=key, key_size=16, root_iv=hashlib.md5(key[:16]).digest())
    assert ec.decide(cs).proven == "oracle:ecryptfs-root-iv"
    cs = crypt_stat(key=key, key_size=16, root_iv=hashlib.md5(key[:32]).digest())
    assert ec.decide(cs).proven == "rejected"


@pytest.mark.parametrize("iv_bytes", [0, 1, 8, 15, 17])
def test_root_iv_oracle_needs_the_kernel_default_16_byte_iv(iv_bytes):
    """A short IV is a weak check (1 byte: a wrong key passes 1 in 256): only 16 counts."""
    wrong = bytes(range(9, 41))
    cs = crypt_stat(iv_bytes=iv_bytes, root_iv=hashlib.md5(FEK).digest()[:iv_bytes])
    verdict = ec.decide(cs)
    assert verdict.proven == "unverified" and verdict.root_iv == "n/a"
    assert "iv_bytes %d != 16" % iv_bytes in verdict.detail
    assert ec.decide(ec.CryptStat(**{**cs.__dict__, "key_area": wrong.ljust(64, b"\0")})).proven == "unverified"


def test_wrong_fek_with_a_1_byte_iv_is_never_proven():
    proven = 0
    for seed in range(600):  # ~2.3 expected false proofs under the old 1..16 rule
        real = hashlib.sha256(b"r%d" % seed).digest()
        wrong = hashlib.sha256(b"w%d" % seed).digest()
        cs = crypt_stat(key=wrong, iv_bytes=1, root_iv=hashlib.md5(real).digest()[:1])
        proven += ec.decide(cs).proven.startswith("oracle:")
    assert proven == 0


@pytest.mark.parametrize("kwargs, why", [
    ({"key": bytes(32), "root_iv": hashlib.md5(bytes(32)).digest()}, "zero key"),
    ({"key_size": 0, "root_iv": hashlib.md5(b"").digest()}, "key_size 0"),
    ({"key_size": 65}, "key_size 65"),
    ({"flags": ec.ECRYPTFS_ENCRYPTED}, "ECRYPTFS_KEY_VALID not set"),
])
def test_unusable_keys_are_never_proven(kwargs, why):
    cs = crypt_stat(**kwargs)
    verdict = ec.decide(cs, ("pass", "tfm AES schedule expands key"))  # even with a schedule "pass"
    assert verdict.proven == "unverified" and why in verdict.detail


def test_zeroed_root_iv_is_not_a_proof():
    verdict = ec.decide(crypt_stat(root_iv=bytes(16)))
    assert verdict.proven == "unverified" and verdict.root_iv == "n/a"


def test_unreadable_crypt_stat_is_an_error():
    assert ec.decide(None).proven == "error:unreadable-crypt_stat"
    assert ec.parse_crypt_stat(b"\0" * 10, 0, EL) is None


# --------------------------------------------------------------------------- tfm schedule


def test_schedule_check_states():
    keyed = crypt_stat(flags=VALID | ec.ECRYPTFS_KEY_SET, tfm=0x2000)
    assert ec.schedule_check([FEK], keyed)[0] == "pass"
    assert ec.schedule_check([bytes(range(5, 37))], keyed)[0] == "fail"
    assert ec.schedule_check([], keyed)[0] == "n/a"
    assert ec.schedule_check(None, keyed)[0] == "n/a"
    assert ec.schedule_check([FEK], crypt_stat(tfm=0x2000))[0] == "n/a"  # KEY_SET unset


def test_schedule_adds_to_and_can_stand_in_for_the_root_iv():
    assert ec.decide(crypt_stat(), ("pass", "")).proven == "oracle:ecryptfs-root-iv+tfm-schedule"
    assert ec.decide(crypt_stat(root_iv=bytes(16)), ("pass", "")).proven == "oracle:ecryptfs-tfm-schedule"


def test_contradicting_schedule_demotes():
    assert ec.decide(crypt_stat(), ("fail", "other key")).proven == "unverified"


def test_schedule_found_in_a_real_crypto_aes_ctx_image():
    ctx = aes.kernel_crypto_aes_ctx(FEK)
    found = dmcrypt.find_aes_schedules(bytes(64) + ctx + bytes(64))
    assert [s.key for s in found] == [FEK] and found[0].full_ctx


# --------------------------------------------------------------------------- offsets


class _NoTypes:
    def get_type(self, name):
        raise exceptions.SymbolError(name, "tbl", "absent")


def test_derived_offsets_never_prove():
    layout = ec.EcryptfsLayout.from_module(_NoTypes())
    assert set(ec.KEY_PATH_KEYS) <= set(layout.key_path_guessed())
    assert "sizeof(ecryptfs_crypt_stat)" in layout.guessed() and layout.source() == "default"
    verdict = ec.decide(crypt_stat(), ("pass", ""), layout.guessed())
    assert verdict.proven == "unverified" and "guessed offsets" in verdict.detail


@pytest.mark.parametrize("schedule", [("n/a", ""), ("fail", "other key")])
def test_a_contradiction_on_guessed_offsets_is_unverified_not_rejected(schedule):
    wrong_iv = hashlib.md5(b"another key").digest()
    verdict = ec.decide(crypt_stat(root_iv=wrong_iv), schedule, ["ecryptfs_crypt_stat.key"])
    assert verdict.proven == "unverified" and "contradicts on guessed offsets" in verdict.detail
    verdict = ec.decide(crypt_stat(), ("fail", "other key"), ["super_block.s_inodes"])
    assert verdict.proven == "unverified" and "contradicts on guessed offsets" in verdict.detail


def test_guessed_walk_offsets_also_demote():
    """The key is still MD5-checked, but its attribution (mount/inode/file) would be guessed."""
    verdict = ec.decide(crypt_stat(), ("pass", ""), ["inode.i_sb_list", "super_block.s_inodes"])
    assert verdict.proven == "unverified" and "inode.i_sb_list" in verdict.detail


def test_btf_memory_layout_is_used_when_the_isf_lacks_the_ecryptfs_types():
    from memdiver.vol3plugins.linux.secrets import btf_memory

    def mk(name, offset):
        values = dict.fromkeys(btf_memory.BtfMember.__dataclass_fields__, 0)
        values.update(name=name, offset=offset)
        return btf_memory.BtfMember(**values)

    structs = {"ecryptfs_crypt_stat": btf_memory.BtfStruct(
        "ecryptfs_crypt_stat", "struct", 320, 1, (mk("key", 120), mk("root_iv", 184)))}
    layout = ec.EcryptfsLayout.from_module(_NoTypes(), structs)
    assert layout["ecryptfs_crypt_stat.key"] == 120 and layout.sources["ecryptfs_crypt_stat.key"] == "btf-memory"
    assert layout.sizes["ecryptfs_crypt_stat"] == 320
    assert layout.size_sources["ecryptfs_crypt_stat"] == "btf-memory"
    assert "sizeof(ecryptfs_crypt_stat)" not in layout.guessed()
    assert "ecryptfs_crypt_stat.key" not in layout.key_path_guessed()
    assert "ecryptfs_crypt_stat.flags" in layout.key_path_guessed()  # not in the BTF: still guessed


def test_container_of_arithmetic():
    assert ec.container_of(0x5000, 0x10) == 0x4FF0
    assert ec.crypt_stat_address(EL, 0x10000) == 0x10000 + 688  # vfs_inode at 0 on 6.8
    shifted = ec.EcryptfsLayout()
    shifted.offsets["ecryptfs_inode_info.vfs_inode"] = 0x40
    assert ec.crypt_stat_address(shifted, 0x10040) == 0x10000 + 688


def test_parse_crypt_stat_reads_the_6_8_layout():
    data = bytearray(304)
    struct.pack_into("<IIQQQQ", data, 0, VALID, 3, 16, 8192, 4096, 32)
    struct.pack_into("<QQ", data, 56, 0xAA, 0xBB)
    data[80:83] = b"aes"
    data[112:144] = FEK
    data[176:192] = hashlib.md5(FEK).digest()
    cs = ec.parse_crypt_stat(bytes(data), 0x9000, EL)
    assert (cs.flags, cs.iv_bytes, cs.key_size, cs.mount_crypt_stat, cs.tfm, cs.cipher) == \
        (VALID, 16, 32, 0xAA, 0xBB, "aes")
    assert cs.key == FEK and ec.decide(cs).proven == "oracle:ecryptfs-root-iv"


# --------------------------------------------------------------------------- synthetic walk


class Mem:
    """A little-endian LP64 address space in a bytearray (addresses start at BASE)."""

    BASE = 0x100000

    def __init__(self, size: int = 0x10000) -> None:
        self.buf = bytearray(size)
        self.cursor = 0x100

    def alloc(self, size: int, align: int = 64) -> int:
        self.cursor = (self.cursor + align - 1) & ~(align - 1)
        address = self.BASE + self.cursor
        self.cursor += size
        return address

    def put(self, address: int, data: bytes) -> None:
        self.buf[address - self.BASE:address - self.BASE + len(data)] = data

    def q(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<Q", value))

    def string(self, text: str) -> int:
        address = self.alloc(len(text) + 1, 8)
        self.put(address, text.encode() + b"\0")
        return address

    def ring(self, head: int, nodes) -> None:
        """A circular ``list_head`` list: head -> nodes... -> head."""
        chain = [head] + list(nodes)
        for here, nxt in zip(chain, chain[1:] + [head]):
            self.q(here, nxt)

    def dentry(self, name: str, parent: int = 0) -> int:
        dentry = self.alloc(192)
        self.q(dentry + EL["dentry.d_parent"], parent or dentry)
        self.q(dentry + EL["dentry.d_name"] + EL["qstr.name"], self.string(name))
        return dentry

    def mount(self, root: int, parent: int = 0, mountpoint: int = 0, devname: str = "") -> int:
        mount = self.alloc(256)
        self.q(mount + EL["mount.mnt"] + EL["vfsmount.mnt_root"], root)
        self.q(mount + EL["mount.mnt_parent"], parent or mount)
        self.q(mount + EL["mount.mnt_mountpoint"], mountpoint or root)
        if devname:
            self.q(mount + EL["mount.mnt_devname"], self.string(devname))
        return mount

    def reader(self) -> dmcrypt.SafeReader:
        context = contexts.Context()
        layer = physical.BufferDataLayer(context, "cfg", "mem", bytes(self.BASE) + bytes(self.buf))
        context.add_layer(layer)
        return dmcrypt.SafeReader(layer, 8, "little")


def _auth_tok_key(mem: Mem, fekek: bytes, sig: str) -> int:
    tok = bytearray(740)
    pw = KL["ecryptfs_auth_tok.token"]
    struct.pack_into("<I", tok, pw + KL["ecryptfs_password.key_bytes"], len(fekek))
    fekek_at, sig_at = pw + KL["ecryptfs_password.fekek"], pw + KL["ecryptfs_password.signature"]
    tok[fekek_at:fekek_at + len(fekek)] = fekek
    tok[sig_at:sig_at + len(sig) + 1] = sig.encode() + b"\0"
    payload = mem.alloc(24 + 740)
    mem.put(payload + KL["user_key_payload.datalen"], struct.pack("<H", 740))
    mem.put(payload + KL["user_key_payload.data"], bytes(tok))
    ktype = mem.alloc(168)
    mem.q(ktype + KL["key_type.name"], mem.string("user"))
    key = mem.alloc(224)
    mem.put(key + KL["key.serial"], struct.pack("<I", 4242))
    mem.q(key + KL["key.type"], ktype)
    mem.q(key + KL["key.description"], mem.string(sig))
    mem.q(key + KL["key.payload"], payload)
    mem.put(key + KL["key.datalen"], struct.pack("<H", 740))
    mem.put(key + KL["key.state"], struct.pack("<h", 1))
    return key


def _inode(mem: Mem, ino: int, cs_bytes: bytes = b"") -> int:
    info = mem.alloc(992)
    mem.q(info + EL["inode.i_ino"], ino)
    mem.put(info + EL["ecryptfs_inode_info.crypt_stat"], cs_bytes or struct.pack("<I", 1))
    return info


def _crypt_stat_bytes(key: bytes, root_iv: bytes) -> bytes:
    data = bytearray(304)
    struct.pack_into("<IIQQQQ", data, 0, VALID, 3, 16, 8192, 4096, len(key))
    data[80:83], data[112:112 + len(key)], data[176:192] = b"aes", key, root_iv
    return bytes(data)


def _world(root_iv: bytes = None):
    """super_blocks -> [ext4 sb, ecryptfs sb]; one file /mnt/gt/f.txt (lower /lower/f.txt) + a dir."""
    mem = Mem()
    fs_ecryptfs, fs_ext4 = mem.alloc(64), mem.alloc(64)
    mem.q(fs_ecryptfs + EL["file_system_type.name"], mem.string("ecryptfs"))
    mem.q(fs_ext4 + EL["file_system_type.name"], mem.string("ext4"))
    head, sb_ext4, sb = mem.alloc(16), mem.alloc(1400), mem.alloc(1400)
    mem.ring(head, [sb_ext4 + EL["super_block.s_list"], sb + EL["super_block.s_list"]])
    mem.q(sb_ext4 + EL["super_block.s_type"], fs_ext4)
    mem.q(sb + EL["super_block.s_type"], fs_ecryptfs)
    # mounts: / (ext4) with /mnt/gt the ecryptfs mount and /lower its lower dir
    root = mem.dentry("/")
    gt = mem.dentry("gt", mem.dentry("mnt", root))
    lower_file = mem.dentry("f.txt", mem.dentry("lower", root))
    root_mount = mem.mount(root)
    upper_root = mem.dentry("/")
    upper_mount = mem.mount(upper_root, root_mount, gt, "/lower")
    mem.ring(sb + EL["super_block.s_mounts"], [upper_mount + EL["mount.mnt_instance"]])
    # sb_info: lower sb s_id + one global auth token whose key is the keyring's auth_tok
    sb_info, lower_sb, tok = mem.alloc(168), mem.alloc(1400), mem.alloc(56)
    mem.q(sb + EL["super_block.s_fs_info"], sb_info)
    mem.q(sb_info + EL["ecryptfs_sb_info.wsi_sb"], lower_sb)
    mem.put(lower_sb + EL["super_block.s_id"], b"vda1\0")
    fekek = bytes(range(64))
    sig = keyring.ecryptfs_signature(fekek)
    mem.ring(sb_info + EL["ecryptfs_sb_info.mount_crypt_stat"] + EL["ecryptfs_mount_crypt_stat.global_auth_tok_list"],
             [tok + EL["ecryptfs_global_auth_tok.mount_crypt_stat_list"]])
    mem.put(tok + EL["ecryptfs_global_auth_tok.sig"], sig.encode() + b"\0")
    mem.q(tok + EL["ecryptfs_global_auth_tok.global_auth_tok_key"], _auth_tok_key(mem, fekek, sig))
    # inodes: a file with a FEK and a directory without one
    file_inode = _inode(mem, 42, _crypt_stat_bytes(FEK, hashlib.md5(FEK).digest() if root_iv is None else root_iv))
    dir_inode = _inode(mem, 7)
    mem.ring(sb + EL["super_block.s_inodes"], [file_inode + EL["inode.i_sb_list"], dir_inode + EL["inode.i_sb_list"]])
    keysig = mem.alloc(40)
    mem.ring(file_inode + EL["ecryptfs_inode_info.crypt_stat"] + EL["ecryptfs_crypt_stat.keysig_list"], [keysig])
    mem.put(keysig + EL["ecryptfs_key_sig.keysig"], sig.encode() + b"\0")
    dentry = mem.dentry("f.txt", upper_root)
    mem.q(file_inode + EL["inode.i_dentry"], dentry + EL["dentry.d_u.d_alias"])
    lower_inode, dinfo = mem.alloc(700), mem.alloc(32)
    mem.q(lower_inode + EL["inode.i_ino"], 99)
    mem.q(file_inode + EL["ecryptfs_inode_info.wii_inode"], lower_inode)
    mem.q(dentry + EL["dentry.d_fsdata"], dinfo)
    mem.q(dinfo + EL["ecryptfs_dentry_info.lower_path"] + EL["path.mnt"], root_mount + EL["mount.mnt"])
    mem.q(dinfo + EL["ecryptfs_dentry_info.lower_path"] + EL["path.dentry"], lower_file)
    plugin = object.__new__(ec.Ecryptfs)
    plugin.reader, plugin.el, plugin.kl, plugin.byteorder = mem.reader(), EL, KL, "little"
    plugin.key_guessed = []
    plugin.crypto = dmcrypt.KernelLayout()
    pages = {}  # struct page -> "physical" address (the synthetic memory is identity-mapped)
    plugin.pc, plugin.phys, plugin.page_to_phys = ec.PagecacheLayout(), plugin.reader, pages.get
    plugin._symbol_address = {"super_blocks": head, "ecryptfs_fs_type": fs_ecryptfs}.get
    return plugin, sig, {"mem": mem, "sb": sb, "file_inode": file_inode, "lower_inode": lower_inode,
                         "pages": pages, "fekek": fekek}


def test_synthetic_walk_finds_proves_and_links_the_fek(monkeypatch):
    monkeypatch.setattr(ec.Ecryptfs, "config", property(lambda self: {}), raising=False)
    plugin, sig, _w = _world()
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv"
    assert record.crypt_stat.key == FEK and record.ino == 42 and record.lower_ino == 99
    assert record.path == "/mnt/gt/f.txt" and record.lower_path == "/lower/f.txt"
    assert record.mount.mountpoint == "/mnt/gt" and record.mount.device == "/lower"
    assert record.mount.lower_dev == "vda1" and record.key_sigs == [sig]
    (tok,) = record.mount.auth_toks
    assert (tok.sig, tok.serial, tok.status) == (sig, 4242, "proven")


def test_synthetic_walk_by_fs_type_name_and_wrong_root_iv(monkeypatch):
    monkeypatch.setattr(ec.Ecryptfs, "config", property(lambda self: {}), raising=False)
    plugin, _sig, _w = _world(root_iv=hashlib.md5(b"another key").digest())
    symbols = {"super_blocks": plugin._symbol_address("super_blocks")}
    plugin._symbol_address = symbols.get  # eCryptfs as a module: no ecryptfs_fs_type symbol
    (record,) = plugin._collect()
    assert record.verdict.proven == "rejected"


@pytest.fixture
def no_config(monkeypatch):
    monkeypatch.setattr(ec.Ecryptfs, "config", property(lambda self: {}), raising=False)


def _layout_guessing(*keys: str) -> ec.EcryptfsLayout:
    layout = ec.EcryptfsLayout(sources=dict.fromkeys(ec._FIELDS, "isf"),
                               size_sources=dict.fromkeys(ec._SIZES, "isf"))
    for key in keys:
        if key.startswith("sizeof("):
            layout.size_sources[key[7:-1]] = "default"
        else:
            layout.sources[key] = "default"
    return layout


@pytest.mark.parametrize("guessed", ["ecryptfs_crypt_stat.key", "ecryptfs_inode_info.crypt_stat",
                                     "sizeof(ecryptfs_crypt_stat)", "super_block.s_inodes",
                                     "inode.i_sb_list"])
def test_guessed_offsets_demote_through_the_record_path(no_config, guessed):
    plugin, _sig, _w = _world()
    plugin.el = _layout_guessing(guessed)
    (record,) = plugin._collect()
    assert record.verdict.proven == "unverified" and guessed in record.verdict.detail
    assert "guessed: " + guessed in plugin._offsets_label()
    assert plugin._row(record)[14] == "unverified"


def test_all_isf_layout_still_proves_and_says_isf(no_config):
    plugin, _sig, _w = _world()
    plugin.el = _layout_guessing()
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv" and plugin._offsets_label() == "isf"


def test_guessed_keyring_offsets_demote_the_auth_token(no_config):
    plugin, sig, _w = _world()
    plugin.key_guessed = ["user_key_payload.data"]
    (record,) = plugin._collect()
    (tok,) = record.mount.auth_toks
    assert tok.status == "unverified:guessed-key-offsets" and "keyring proven" not in tok.describe()


def _add_tfm(w, ctx_key: bytes) -> None:
    """crypt_stat->tfm = a keyed ``cbc(aes)`` skcipher whose ctx holds ``ctx_key``'s crypto_aes_ctx."""
    mem, kl = w["mem"], dmcrypt.KernelLayout()
    skcipher, alg = mem.alloc(64 + 600), mem.alloc(256)
    tfm = skcipher + kl["crypto_skcipher.base"]
    mem.q(tfm + kl["crypto_tfm.__crt_alg"], alg)
    mem.put(alg + kl["crypto_alg.cra_ctxsize"], struct.pack("<I", 484))
    mem.put(alg + kl["crypto_alg.cra_name"], b"cbc(aes)\0")
    mem.put(alg + kl["crypto_alg.cra_driver_name"], b"cbc-aes-synthetic\0")
    mem.put(tfm + kl["crypto_tfm.__crt_ctx"], aes.kernel_crypto_aes_ctx(ctx_key))
    cs = w["file_inode"] + EL["ecryptfs_inode_info.crypt_stat"]
    mem.put(cs + EL["ecryptfs_crypt_stat.flags"], struct.pack("<I", VALID | ec.ECRYPTFS_KEY_SET))
    mem.q(cs + EL["ecryptfs_crypt_stat.tfm"], skcipher)


def test_schedule_proof_end_to_end_through_a_synthetic_tfm(no_config):
    plugin, _sig, w = _world()
    _add_tfm(w, FEK)
    plugin.reader = w["mem"].reader()
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv+tfm-schedule"
    assert record.verdict.schedule == "pass"


def test_schedule_of_another_key_demotes_end_to_end(no_config):
    plugin, _sig, w = _world()
    _add_tfm(w, bytes(range(50, 82)))
    plugin.reader = w["mem"].reader()
    (record,) = plugin._collect()
    assert record.verdict.proven == "unverified" and record.verdict.schedule == "fail"


def test_guessed_crypto_layout_never_consults_the_schedule(no_config):
    plugin, _sig, w = _world()
    _add_tfm(w, FEK)
    plugin.reader = w["mem"].reader()
    plugin.crypto = dmcrypt.KernelLayout(sources={"crypto_tfm.__crt_ctx": "default"})
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv" and record.verdict.schedule == "n/a"
    assert "tfm schedule not checked" in record.verdict.detail


def _unreadable_inodes(mem: Mem, count: int):
    """Inodes whose ``i_sb_list`` is readable but whose crypt_stat runs past the end of memory."""
    end = mem.BASE + len(mem.buf)
    return [end - 300 - 16 * k for k in range(count)]


def test_unreadable_crypt_stat_rows_and_the_run_cap(no_config, monkeypatch):
    monkeypatch.setattr(ec, "MAX_UNREADABLE_RUN", 2)
    plugin, _sig, w = _world()
    mem = w["mem"]
    bad = _unreadable_inodes(mem, 4)
    mem.ring(w["sb"] + EL["super_block.s_inodes"],
             [w["file_inode"] + EL["inode.i_sb_list"]] + [b + EL["inode.i_sb_list"] for b in bad])
    plugin.reader = mem.reader()
    records = plugin._collect()
    assert [r.verdict.proven for r in records] == [
        "oracle:ecryptfs-root-iv", "error:unreadable-crypt_stat", "error:unreadable-crypt_stat",
        "error:unreadable-run"]
    assert "walk of this mount stopped" in records[-1].verdict.detail
    assert all(plugin._row(r)[14] == r.verdict.proven for r in records)  # rows render


def test_mount_root_path_is_resolved_once_per_mount(no_config, monkeypatch):
    plugin, _sig, _w = _world()
    calls = []
    original = ec.mount_path
    monkeypatch.setattr(ec, "mount_path", lambda *a: calls.append(a[-1]) or original(*a))
    plugin._collect()
    plugin._collect()
    assert len(calls) == len(set(calls)) == 2  # the ecryptfs mount and the lower mount, once each


def test_dentry_parent_cycle_gives_no_path():
    mem = Mem()
    a, b = mem.dentry("a"), mem.dentry("b")
    mem.q(a + EL["dentry.d_parent"], b)
    mem.q(b + EL["dentry.d_parent"], a)
    root = mem.dentry("/")
    mount = mem.mount(root)
    reader = mem.reader()
    assert ec.dentry_parts(reader, EL, a, root) is None
    assert ec.mount_path(reader, EL, a, mount) is None


def test_mount_parent_cycle_gives_no_path():
    mem = Mem()
    r1, r2 = mem.dentry("/"), mem.dentry("/")
    m1, m2 = mem.mount(r1), mem.mount(r2)
    mem.q(m1 + EL["mount.mnt_parent"], m2)
    mem.q(m2 + EL["mount.mnt_parent"], m1)
    mem.q(m1 + EL["mount.mnt_mountpoint"], r2)
    mem.q(m2 + EL["mount.mnt_mountpoint"], r1)
    assert ec.mount_path(mem.reader(), EL, r1, m1) is None


def test_deep_dentry_chain_is_bounded():
    mem = Mem(0x40000)
    root = mem.dentry("/")
    dentry = root
    for depth in range(ec.MAX_PATH_PARTS + 5):
        dentry = mem.dentry("d%d" % depth, dentry)
    assert ec.dentry_parts(mem.reader(), EL, dentry, root) is None


def test_corrupt_keysig_lists_are_bounded():
    mem = Mem()
    cs = mem.alloc(304)
    head = cs + EL["ecryptfs_crypt_stat.keysig_list"]
    a, b = mem.alloc(40), mem.alloc(40)
    mem.q(head, a)
    mem.q(a, b)
    mem.q(b, a)  # cycle that skips the head
    for item in (a, b):
        mem.put(item + EL["ecryptfs_key_sig.keysig"], b"0123456789abcdef\0")
    assert ec.key_sigs(mem.reader(), EL, cs) == ["0123456789abcdef"] * 2
    items = [mem.alloc(40) for _ in range(ec.MAX_KEYSIGS * 3)]
    mem.ring(head, items)
    for item in items:
        mem.put(item + EL["ecryptfs_key_sig.keysig"], b"0123456789abcdef\0")
    assert len(ec.key_sigs(mem.reader(), EL, cs)) == ec.MAX_KEYSIGS


def test_corrupt_auth_token_lists_are_bounded_and_survive_bad_keys():
    mem = Mem(0x20000)
    sb_info = mem.alloc(168)
    head = sb_info + EL["ecryptfs_sb_info.mount_crypt_stat"] + EL["ecryptfs_mount_crypt_stat.global_auth_tok_list"]
    toks = [mem.alloc(56) for _ in range(ec.MAX_AUTH_TOKS * 2)]
    mem.ring(head, [t + EL["ecryptfs_global_auth_tok.mount_crypt_stat_list"] for t in toks])
    for tok in toks:
        mem.q(tok + EL["ecryptfs_global_auth_tok.global_auth_tok_key"], 0xDEAD0000)  # unreadable key
    found = ec.mount_auth_toks(mem.reader(), EL, KL, sb_info)
    assert len(found) == ec.MAX_AUTH_TOKS
    assert all(t.serial is None and t.status == "n/a" and t.sig == "?" for t in found)
    first = toks[0] + EL["ecryptfs_global_auth_tok.mount_crypt_stat_list"]
    mem.q(head, first)
    mem.q(first, first)  # self-loop
    assert len(ec.mount_auth_toks(mem.reader(), EL, KL, sb_info)) == 1


def test_list_walk_is_cycle_safe_and_bounded():
    mem = Mem()
    head, a, b = mem.alloc(16), mem.alloc(16), mem.alloc(16)
    mem.q(head, a)
    mem.q(a, b)
    mem.q(b, a)  # cycle that never returns to head
    assert list(ec.iter_list(mem.reader(), head, 0, 100)) == [a, b]
    mem.ring(head, [mem.alloc(16) for _ in range(10)])
    assert len(list(ec.iter_list(mem.reader(), head, 0, 4))) == 4


# --------------------------------------------------------------------------- real captures (gated)

CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
X86_STEMS = ("ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic",
             "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic")
ALT_VOL_PY = os.environ.get("MEMDIVER_VOL3_ALT_VOL_PY", "")
TAG3, TAG3_VERSION, S2K_SALTED_ITERATED = 0x8C, 0x04, 0x03
PACKET_SET_OFFSET = 26  # size(8) + marker(8) + flags(4) + header extent size(4) + extents at front(2)


def _stock_vol() -> str:
    return (os.environ.get("MEMDIVER_VOL3_VOL") or shutil.which("vol")
            or str(Path(sys.executable).with_name("vol")))


def wrapped_fek(header: bytes) -> bytes:
    """The encrypted session key of the tag-3 packet at the start of an eCryptfs lower file."""
    pos = PACKET_SET_OFFSET
    assert header[pos] == TAG3, "no tag-3 packet"
    length = header[pos + 1]
    pos += 2
    if length >= 192:
        length, pos = ((length - 192) << 8) + header[pos] + 192, pos + 1
    body = header[pos:pos + length]
    assert body[0] == TAG3_VERSION and body[2] == S2K_SALTED_ITERATED
    return body[13:]  # version, cipher code, s2k, hash, salt[8], count


def test_wrapped_fek_parser_round_trips():
    fekek, fek = bytes(range(64)), bytes(range(7, 39))
    enc = aes.ecb_encrypt(fekek[:32], fek)
    body = bytes([TAG3_VERSION, 0x09, S2K_SALTED_ITERATED, 0x01]) + bytes(8) + b"\x60" + enc
    header = bytes(PACKET_SET_OFFSET) + bytes([TAG3, len(body)]) + body
    assert aes.ecb_decrypt(fekek[:32], wrapped_fek(header)) == fek


# --------------------------------------------------------------------------- lower header: tag 3 in the plugin

FEKEK = bytes(range(64))
SIG = "14a71fe0c567aa7e"
SALT = bytes.fromhex("0011223344556677")


def _length(size: int) -> bytes:
    """keystore.c ``ecryptfs_write_packet_length``."""
    return bytes([size]) if size < 192 else bytes([(size - 192) // 256 + 192, (size - 192) % 256])


def tag3_packet(fek: bytes = FEK, fekek: bytes = FEKEK, code: int = 0x09, wrapped: bytes = None,
                version: int = TAG3_VERSION, s2k: int = S2K_SALTED_ITERATED) -> bytes:
    """keystore.c ``write_tag_3_packet`` (AES-192 FEKs are wrapped padded to 32 bytes)."""
    if wrapped is None:
        size = ec.AES_CIPHER_CODES.get(code, len(fek))
        wrapped = aes.ecb_encrypt(fekek[:size], fek.ljust(-(-len(fek) // 16) * 16, b"\0"))
    body = bytes([version, code, s2k, 0x01]) + SALT + b"\x60" + wrapped
    return bytes([TAG3]) + _length(len(body)) + body


def tag11_packet(sig: str = SIG) -> bytes:
    body = bytes([0x62, 8]) + b"_CONSOLE" + bytes(4) + bytes.fromhex(sig)
    return bytes([0xED]) + _length(len(body)) + body


def tag1_packet() -> bytes:
    body = bytes([0x03]) + bytes.fromhex(SIG) + bytes([0x01]) + bytes(40)
    return bytes([0x01]) + _length(len(body)) + body


def lower_header(*packets: bytes, marker: bool = True) -> bytes:
    """crypto.c ``ecryptfs_write_headers_virt``: size, marker, flags, extent size/count, packets, 0."""
    m1 = 0x12345678
    head = struct.pack(">Q", 4096) + struct.pack(">II", m1, m1 ^ (0x3C81B7F5 if marker else 1))
    head += struct.pack(">IIH", 0x03000002, 8192, 1)
    packets = packets or (tag3_packet(), tag11_packet())
    return (head + b"".join(packets) + b"\0").ljust(4096, b"\0")


def test_parse_tag3_reads_a_kernel_format_header():
    tag3 = ec.parse_tag3(lower_header())
    assert (tag3.cipher_code, tag3.key_bytes, tag3.salt, tag3.count, tag3.sig) == (0x09, 32, SALT, 65536, SIG)
    assert aes.ecb_decrypt(FEKEK[:32], tag3.wrapped) == FEK


@pytest.mark.parametrize("code,size", [(0x07, 16), (0x08, 24), (0x09, 32)])
def test_tag3_check_aes_key_sizes(code, size):
    fek = FEK[:size]
    header = lower_header(tag3_packet(fek, code=code), tag11_packet())
    assert ec.parse_tag3(header).key_bytes == size
    assert len(ec.parse_tag3(header).wrapped) == (32 if size == 24 else size)
    assert ec.tag3_check(header, FEKEK, fek) == ("pass", "tag-3 (sig %s) unwraps to the FEK" % SIG)
    assert ec.tag3_check(header, bytes(64), fek)[0] == "fail"
    assert ec.tag3_check(header, FEKEK, bytes(range(5, 5 + size)))[0] == "fail"


def test_packet_length_both_encodings_and_unsupported_forms():
    assert ec.packet_length(bytes([45]), 0) == (45, 1)
    assert ec.packet_length(bytes([191]), 0) == (191, 1)
    assert ec.packet_length(_length(253), 0) == (253, 2) and _length(253) == bytes([192, 61])
    assert ec.packet_length(_length(8383), 0) == (8383, 2)
    assert ec.packet_length(bytes([192]), 0) is None  # truncated two-byte length
    assert ec.packet_length(bytes([224, 0]), 0) is None and ec.packet_length(bytes([255, 0, 0, 0, 1]), 0) is None
    assert ec.packet_length(b"", 0) is None


def test_two_byte_tag3_length_is_parsed():
    wrapped = aes.ecb_encrypt(FEKEK[:32], FEK) + bytes(208)  # body 13 + 240 = 253 bytes
    header = lower_header(tag3_packet(wrapped=wrapped), tag11_packet())
    assert header[ec.PACKET_SET_OFFSET + 1] == 192
    assert ec.parse_tag3(header).wrapped == wrapped and ec.parse_tag3(header).sig == SIG
    assert ec.tag3_check(header, FEKEK, FEK)[0] == "pass"


def test_tag3_n_a_cases():
    assert ec.tag3_check(lower_header(marker=False), FEKEK, FEK) == (
        "n/a", "no eCryptfs header marker in lower page 0 (metadata in xattr?)")
    assert ec.parse_tag3(lower_header(marker=False)) is None
    assert ec.tag3_check(lower_header(tag1_packet()), FEKEK, FEK) == ("n/a", "tag-1 (public-key) packet: tag-3 n/a")
    assert ec.tag3_check(lower_header(tag11_packet()), FEKEK, FEK) == ("n/a", "no tag-3 packet in the lower header")
    assert ec.tag3_check(lower_header(), b"", FEK)[0] == "n/a"
    assert ec.tag3_check(lower_header(), FEKEK, b"")[0] == "n/a"
    twofish = lower_header(tag3_packet(code=0x0A), tag11_packet())
    assert ec.parse_tag3(twofish).key_bytes is None
    assert ec.tag3_check(twofish, FEKEK, FEK) == ("n/a", "tag-3 not checkable (cipher code 0xa, 32 wrapped bytes)")
    assert ec.tag3_check(lower_header(), FEKEK[:16], FEK)[0] == "n/a"  # FEKEK shorter than the key
    assert ec.tag3_check(b"", FEKEK, FEK)[0] == "n/a"


def test_malformed_tag3_packets_are_skipped_not_fatal():
    assert ec.parse_tag3(lower_header(tag3_packet(version=3))) is None
    assert ec.parse_tag3(lower_header(tag3_packet(s2k=1))) is None
    truncated = lower_header()[:ec.PACKET_SET_OFFSET + 20]
    assert ec.parse_tag3(truncated) is None and list(ec.iter_packets(truncated)) == []
    no_sig = lower_header(tag3_packet())
    assert ec.parse_tag3(no_sig).sig is None and ec.tag3_check(no_sig, FEKEK, FEK) == (
        "pass", "tag-3 unwraps to the FEK")


def test_tag3_cipher_code_naming_another_key_size_fails():
    header = lower_header(tag3_packet(FEK[:16], code=0x07), tag11_packet())
    assert ec.tag3_check(header, FEKEK, FEK)[0] == "fail"  # crypt_stat holds a 32-byte key


def test_second_tag3_packet_of_another_fekek_is_also_tried():
    other = bytes(range(100, 164))
    header = lower_header(tag3_packet(fekek=other), tag11_packet("00" * 8), tag3_packet(), tag11_packet())
    assert [t.sig for t in ec.parse_tag3s(header)] == ["00" * 8, SIG]
    assert ec.tag3_check(header, FEKEK, FEK)[0] == "pass" and ec.tag3_check(header, other, FEK)[0] == "pass"


def test_plugin_tag3_agrees_with_the_test_helper_on_the_fixtures():
    """Cross-check: ``wrapped_fek`` (the ground-truth helper) and the plugin read the same packet."""
    fixtures = [lower_header(), lower_header(tag3_packet(FEK[:16], code=0x07), tag11_packet()),
                lower_header(tag3_packet(FEK[:24], code=0x08)),
                lower_header(tag3_packet(wrapped=aes.ecb_encrypt(FEKEK[:32], FEK) + bytes(208)))]
    for header in fixtures:
        tag3 = ec.parse_tag3(header)
        assert tag3.wrapped == wrapped_fek(header)
        for fekek in (FEKEK, bytes(64)):
            plain = aes.ecb_decrypt(fekek[:tag3.key_bytes], wrapped_fek(header))[:tag3.key_bytes]
            expected = "pass" if plain == FEK[:tag3.key_bytes] else "fail"
            assert ec.tag3_check(header, fekek, FEK[:tag3.key_bytes])[0] == expected


# --------------------------------------------------------------------------- decide(tag3=)


def test_tag3_pass_appends_to_the_proof_label():
    assert ec.decide(crypt_stat(), tag3=("pass", "t")).proven == "oracle:ecryptfs-root-iv+ecryptfs-tag3"
    sched = ("pass", "s")
    assert ec.decide(crypt_stat(), sched, tag3=("pass", "t")).proven == \
        "oracle:ecryptfs-root-iv+tfm-schedule+ecryptfs-tag3"
    no_iv = crypt_stat(root_iv=bytes(16))
    assert ec.decide(no_iv, sched, tag3=("pass", "t")).proven == "oracle:ecryptfs-tfm-schedule+ecryptfs-tag3"
    verdict = ec.decide(no_iv, tag3=("pass", "t"))
    assert (verdict.proven, verdict.tag3) == ("oracle:ecryptfs-tag3", "pass") and "t" in verdict.detail


def test_tag3_fail_with_root_iv_keeps_the_fek_and_flags_the_pairing():
    verdict = ec.decide(crypt_stat(), tag3=("fail", "tag-3 unwrapped with FEKEK x != FEK"))
    assert verdict.proven == "oracle:ecryptfs-root-iv" and verdict.tag3 == "fail"
    assert "pairing NOT confirmed" in verdict.detail


def test_tag3_fail_without_root_iv_is_unverified():
    no_iv = crypt_stat(root_iv=bytes(16))
    assert ec.decide(no_iv, tag3=("fail", "x")).proven == "unverified"
    verdict = ec.decide(no_iv, ("pass", "s"), tag3=("fail", "x"))
    assert verdict.proven == "unverified" and "tag-3 contradicts" in verdict.detail


def test_tag3_never_rejects_and_never_proves_on_guessed_offsets():
    assert ec.decide(crypt_stat(), tag3=("n/a", ec.NOT_RESIDENT)).proven == "oracle:ecryptfs-root-iv"
    wrong_iv = crypt_stat(root_iv=hashlib.md5(b"x").digest())
    assert ec.decide(wrong_iv, tag3=("pass", "t")).proven == "rejected"  # the root IV still rules
    guessed = ec.decide(crypt_stat(), tag3=("pass", "t"), guessed=["inode.i_sb_list"])
    assert guessed.proven == "unverified"
    assert "contradicts" in ec.decide(crypt_stat(), tag3=("fail", "t"), guessed=["x"]).detail
    unusable = ec.decide(crypt_stat(flags=0), tag3=("pass", "t"))
    assert unusable.proven == "unverified" and unusable.tag3 == "n/a"


def _tok(sig: str, fekek: bytes = None, status: str = "proven", flags: int = 0) -> ec.AuthTok:
    return ec.AuthTok(sig, flags, 0x1000, 1, status, fekek)


def test_tag3_with_auth_toks():
    header = lower_header()
    assert ec.tag3_with_auth_toks(header, [], FEK)[0] == "n/a"
    assert ec.tag3_with_auth_toks(header, [_tok(SIG)], FEK) == (
        "n/a", "tag-3 n/a: no FEKEK decoded from the mount auth tokens")
    both = [_tok("00" * 8, bytes(64)), _tok(SIG, FEKEK)]
    assert ec.tag3_with_auth_toks(header, both, FEK) == ("pass", "tag-3 (sig %s) unwraps to the FEK" % SIG)
    assert ec.tag3_with_auth_toks(lower_header(tag3_packet()), both, FEK) == (
        "pass", "tag-3 unwraps to the FEK with FEKEK %s" % SIG)
    assert ec.tag3_with_auth_toks(header, both[:1], FEK) == (
        "fail", "tag-3 unwrapped with FEKEK %s != FEK" % ("00" * 8))
    assert ec.tag3_with_auth_toks(lower_header(tag1_packet()), both, FEK)[0] == "n/a"


# --------------------------------------------------------------------------- tag 3 through the record path


MAPPING_PAGE = 0x40  # page.mapping at 24 in a 64-byte struct page


def _resident(plugin, w, header: bytes, owner: int = None) -> None:
    """Put ``header`` in page 0 of the lower inode's page cache (``xa_head`` = the page itself)."""
    mem, pc = w["mem"], plugin.pc
    mapping, page, data = mem.alloc(200), mem.alloc(64), mem.alloc(4096, 4096)
    mem.q(w["lower_inode"] + pc["inode.i_mapping"], mapping)
    mem.q(mapping + pc["address_space.i_pages"] + pc["xarray.xa_head"], page)
    mem.q(page + pc["page.mapping"], owner if owner is not None else mapping)
    mem.put(data, header)
    w["pages"][page] = data
    plugin.reader = plugin.phys = mem.reader()


def _world_big():
    plugin, sig, w = _world()
    w["mem"].buf.extend(bytes(0x10000))
    plugin.reader = plugin.phys = w["mem"].reader()
    return plugin, sig, w


def test_record_path_proves_tag3_from_the_lower_page_cache(no_config):
    plugin, sig, w = _world_big()
    _resident(plugin, w, lower_header(tag3_packet(fekek=w["fekek"]), tag11_packet(sig)))
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv+ecryptfs-tag3" and record.verdict.tag3 == "pass"
    assert plugin.lower_header(w["lower_inode"])[:8] == struct.pack(">Q", 4096)
    assert "pairing" not in plugin._row(record)[13]
    assert record.mount.auth_toks[0].fekek == w["fekek"]


def test_record_path_not_resident_is_n_a_never_rejected(no_config):
    plugin, _sig, _w = _world_big()
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv" and record.verdict.tag3 == "n/a"
    assert "tag-3 n/a: " + ec.NOT_RESIDENT in record.verdict.detail


def test_record_path_skips_a_stale_page_of_another_file(no_config):
    plugin, sig, w = _world_big()
    _resident(plugin, w, lower_header(tag3_packet(fekek=w["fekek"]), tag11_packet(sig)), owner=0xFFFF888000777000)
    (record,) = plugin._collect()
    assert record.verdict.tag3 == "n/a" and ec.NOT_RESIDENT in record.verdict.detail


def test_record_path_tag3_of_another_fekek_flags_the_pairing(no_config):
    plugin, sig, w = _world_big()
    _resident(plugin, w, lower_header(tag3_packet(fekek=bytes(64)), tag11_packet(sig)))
    (record,) = plugin._collect()
    assert record.verdict.proven == "oracle:ecryptfs-root-iv" and record.verdict.tag3 == "fail"
    row = plugin._row(record)
    assert row[13].startswith(sig + " fekek") and row[13].endswith("FEKEK pairing NOT confirmed (tag-3 of this file)")
    assert "pairing NOT confirmed" in row[15]


def test_record_path_tag3_fail_on_guessed_page_cache_offsets_is_n_a(no_config):
    plugin, sig, w = _world_big()
    _resident(plugin, w, lower_header(tag3_packet(fekek=bytes(64)), tag11_packet(sig)))
    plugin.pc = ec.PagecacheLayout(sources={"page.mapping": "default"})
    (record,) = plugin._collect()
    assert record.verdict.tag3 == "n/a" and "guessed page-cache offsets (page.mapping)" in record.verdict.detail


def test_pagecache_layout_reads_the_isf():
    class Module:
        def get_type(self, name):
            raise exceptions.SymbolError(name, "m", "absent")

    layout = ec.PagecacheLayout.from_module(Module())
    assert layout.defaulted() == sorted(ec._PAGECACHE_FIELDS)
    assert layout["inode.i_mapping"] == 64 and layout["sizeof(page)"] == 64


# --------------------------------------------------------------------------- exports


class _Out:
    def __init__(self):
        self.files = {}

    def open(self, name):
        import io

        files = self.files

        class Handle(io.BytesIO):
            def close(self):
                files[name] = self.getvalue()
                super().close()

        return Handle()


def _records_for_export():
    plugin, sig, w = _world_big()
    _resident(plugin, w, lower_header(tag3_packet(fekek=w["fekek"]), tag11_packet(sig)))
    (proven,) = plugin._collect()
    unproven = ec.FileRecord(proven.mount, 0, 1, 0, None, 0, 5, "/lower/x,y", crypt_stat(flags=0), [],
                             ec.FekVerdict("unverified", ""))
    return plugin, sig, w, [proven, unproven]


def test_fek_csv_lists_proven_feks_only(no_config):
    plugin, _sig, _w, records = _records_for_export()
    assert ec.Ecryptfs.fek_csv(records) == "lower_path,inode,cipher,fek_hex\n/lower/f.txt,99,aes,%s\n" % FEK.hex()
    quoted = ec.FileRecord(**dict(records[0].__dict__, lower_path="/lower/a,b"))
    assert '"/lower/a,b",99,aes,' in ec.Ecryptfs.fek_csv([quoted])


def test_fekek_lines_lists_keyring_proven_fekeks_once(no_config):
    _plugin, sig, w, records = _records_for_export()
    assert ec.Ecryptfs.fekek_lines(records) == "%s %s\n" % (sig, w["fekek"].hex())
    mount = ec.Mount(0, 0, "d", None, None, None, "", [_tok("aa" * 8, bytes(8), "unverified"),
                                                       _tok("bb" * 8, bytes(8), "proven", ec.ECRYPTFS_AUTH_TOK_INVALID),
                                                       _tok("cc" * 8, None)])
    other = ec.FileRecord(mount, 0, 0, 0, None, 0, None, None, None, [], ec.FekVerdict("unverified", ""))
    assert ec.Ecryptfs.fekek_lines([other]) == ""


@pytest.mark.parametrize("mode,name", [("fek", "ecryptfs_fek.csv"), ("fekek", "ecryptfs_fekek.txt"),
                                       ("json", "ecryptfs.json")])
def test_export_modes_write_one_file(monkeypatch, mode, name):
    monkeypatch.setattr(ec.Ecryptfs, "config", property(lambda self: {"export": mode}), raising=False)
    plugin, _sig, _w, records = _records_for_export()
    out = _Out()
    monkeypatch.setattr(ec.Ecryptfs, "open", property(lambda self: out.open))
    plugin.arch = "x86_64"
    plugin._export(records)
    assert list(out.files) == [name]
    if mode == "json":
        report = json.loads(out.files[name])
        assert [f["tag3"] for f in report["files"]] == ["pass", "n/a"]
        assert report["pagecache_offset_sources"] == {}
    elif mode == "fek":
        assert out.files[name].decode().splitlines()[1].endswith(FEK.hex())


def test_no_export_writes_nothing(no_config, monkeypatch):
    plugin, _sig, _w, records = _records_for_export()
    out = _Out()
    monkeypatch.setattr(ec.Ecryptfs, "open", property(lambda self: out.open))
    plugin._export(records)
    assert out.files == {}


def _argv(vol: str, tmp_path: Path, stem: str, cache: str, out: Path, *args: str):
    head = [sys.executable, vol] if vol.endswith(".py") else [vol]
    return head + ["-q", "-r", "json", "--cache-path", str(tmp_path / cache), "-s", str(tmp_path / "sym"),
                   "-p", str(REPO / "vol3plugins"), "-f", str(CAPTURE_DIR / (stem + ".lime")),
                   "-o", str(out), *args]


def _run(argv, cwd: Path) -> list:
    result = subprocess.run(argv, capture_output=True, text=True, cwd=str(cwd), timeout=1800)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout[result.stdout.index("["):])


def _setup(tmp_path: Path, stem: str) -> None:
    linux = tmp_path / "sym" / "linux"
    linux.mkdir(parents=True)
    (linux / (stem + ".json")).symlink_to(CAPTURE_DIR / (stem + ".isf.json"))
    for name in ("cache", "cache_alt", "out", "dumps"):
        (tmp_path / name).mkdir()


def _lower_header(vol: str, tmp_path: Path, stem: str, inode: int) -> bytes:
    dumps = tmp_path / "dumps"
    _run(_argv(vol, tmp_path, stem, "cache", dumps, "linux.pagecache.InodePages", "--inode", str(inode),
               "--dump"), tmp_path)
    (dumped,) = [p for p in dumps.glob("inode_*.dmp") if (int(p.stem[6:], 16) ^ inode) & ((1 << 47) - 1) == 0]
    return dumped.read_bytes()


@pytest.mark.parametrize("stem", X86_STEMS)
def test_real_x86_capture_feks_proven_and_match_lower_headers(tmp_path, stem):
    vol, sidecar = _stock_vol(), CAPTURE_DIR / (stem + ".secrets.json")
    if not ((CAPTURE_DIR / (stem + ".lime")).is_file() and sidecar.is_file() and Path(vol).is_file()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture or stock `vol` not present")
    truth = json.loads(sidecar.read_text())["ecryptfs"][0]
    _setup(tmp_path, stem)
    rows = _run(_argv(vol, tmp_path, stem, "cache", tmp_path / "out", "linux.ecryptfs", "--export", "json"),
                tmp_path)
    proven = [r for r in rows if r["Proven"].startswith("oracle:")]
    assert proven and all(r["Offsets"] == "isf" for r in rows)
    assert all(r["Mount"] == truth["mountpoint"] and r["Source"] == truth["lower_dir"] for r in rows)
    assert all(r["MountAuthTok"].startswith(truth["fekek_signature"] + " fekek") and "keyring proven"
               in r["MountAuthTok"] and r["KeySigs"] == truth["fekek_signature"] for r in rows)
    report = json.loads((tmp_path / "out" / "ecryptfs.json").read_text())
    assert len(report["files"]) == len(rows)
    fekek = bytes.fromhex(truth["fekek_hex"])
    by_crypt_stat = {f["crypt_stat"]: f for f in report["files"]}
    for row in proven:  # ground truth: the FEK wrapped in the lower file's own header
        header = _lower_header(vol, tmp_path, stem, row["LowerInodeAddr"])
        assert aes.ecb_decrypt(fekek[:row["KeySize"]], wrapped_fek(header)).hex() == row["KeyHex"], row["Path"]
        tag3 = ec.parse_tag3(header)  # the plugin's own parser agrees with the helper on real headers
        assert (tag3.wrapped, tag3.sig, tag3.salt.hex()) == (
            wrapped_fek(header), truth["fekek_signature"], truth["salt_hex"])
        tag3_status = by_crypt_stat[row["CryptStat(V)"]]["tag3"]
        assert (tag3_status == "pass" and row["Proven"].endswith("+ecryptfs-tag3")) or (
            tag3_status == "n/a" and ec.NOT_RESIDENT in row["Detail"]), row
    if ALT_VOL_PY and Path(ALT_VOL_PY).is_file():
        alt = _run(_argv(ALT_VOL_PY, tmp_path, stem, "cache_alt", tmp_path / "out", "linux.ecryptfs"), tmp_path)
        assert sorted((r["Path"], r["KeyHex"], r["Proven"]) for r in alt) == \
            sorted((r["Path"], r["KeyHex"], r["Proven"]) for r in rows)


def test_fallback_layout_equals_the_capture_isf_and_pahole():
    stem = X86_STEMS[0]
    isf, sidecar = CAPTURE_DIR / (stem + ".isf.json"), CAPTURE_DIR / (stem + ".secrets.json")
    if not (isf.is_file() and sidecar.is_file()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture not present")
    types = json.loads(isf.read_text())["user_types"]

    def offset(type_name, path):
        total = 0
        for member in path:
            fields = types[type_name]["fields"]
            if member not in fields:
                inner = [(n, f) for n, f in fields.items() if n.startswith("unnamed_field")
                         and member in types[f["type"]["name"]]["fields"]]
                (_n, spec), = inner
                total += spec["offset"]
                type_name, fields = spec["type"]["name"], types[spec["type"]["name"]]["fields"]
            total += fields[member]["offset"]
            type_name = fields[member]["type"].get("name", type_name)
        return total

    for key, fallback in ec._FIELDS.items():
        type_name, *path = key.split(".")
        assert offset(type_name, path) == fallback, key
    pahole = json.loads(sidecar.read_text())["btf_offsets"]["ecryptfs_crypt_stat"]
    for key, fallback in ec._FIELDS.items():
        if key.startswith("ecryptfs_crypt_stat."):
            assert pahole["members"][key.split(".", 1)[1]]["offset"] == fallback, key
    assert pahole["size"] == ec._SIZES["ecryptfs_crypt_stat"] == types["ecryptfs_crypt_stat"]["size"]


def test_csv_field_quotes_like_the_csv_module():
    import csv
    import io

    for text in ("/lower/plain", "/lower/a,b", 'say "hi"', "line\nbreak", ""):
        out = io.StringIO()
        csv.writer(out, lineterminator="\n").writerow([text, "x"])
        assert ec.csv_field(text) + ",x\n" == out.getvalue()
