"""``linux.fscrypt`` (``vol3plugins/linux/fscrypt.py``).

Unit tests lay out synthetic kernel memory (the ``tests/test_vol3plugins_linux_dmcrypt.py``
``Mem``/``make_tfm`` helpers, LP64 v6.8 offsets): ``super_blocks`` -> ``super_block`` ->
``fscrypt_keyring`` -> ``fscrypt_master_key`` -> ``mk_decrypted_inodes`` ->
``fscrypt_inode_info`` with an ``xts(aes)`` / ``cts(cbc(aes))`` transform holding the per-file
key schedules, and an ``hmac(sha512)`` transform holding the HKDF-PRK pads for v2 keys.  The
corpus tests run the plugin on the real x86_64 acquired-secrets captures
(``MEMDIVER_SECRETS_CORPUS`` = absolute capture directory) under stock vol (``vol`` on PATH or
``MEMDIVER_VOL3_BIN``) and a second tree (``MEMDIVER_VOL3_ALT_VOL_PY``); each skips cleanly.
"""

import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import exceptions  # noqa: E402

from memdiver.vol3plugins.linux import dmcrypt, fscrypt, kernel_common  # noqa: E402
from memdiver.vol3plugins.linux.secrets import aes  # noqa: E402
from memdiver.vol3plugins.linux.secrets import hkdf_midstate as hk  # noqa: E402
from tests.test_vol3plugins_linux_dmcrypt import Mem, make_tfm, xts_ce_ctx  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FL = fscrypt.FscryptLayout()
KL = dmcrypt.KernelLayout()
V1_KEY = bytes(range(0x40, 0x80))
V2_KEY = bytes(range(0xC0, 0x100))
DESCRIPTOR = bytes.fromhex("0123456789abcdef")
XTS, CTS = 1, 4


# --------------------------------------------------------------------------- synthetic image


def sha512_export(state) -> bytes:
    """``struct sha512_state`` export after one block: state, count = (128, 0), buf."""
    return struct.pack("<8Q", *state) + struct.pack("<2Q", 128, 0) + bytes(128)


class Image:
    """One ext4 superblock with an fscrypt keyring; keys/inodes are added by the tests."""

    def __init__(self, fl=FL) -> None:
        self.fl = fl
        self.mem = Mem(0x40000)
        mem = self.mem
        self.head = mem.alloc(16)
        self.sb = mem.alloc(1100)
        fs_type = mem.alloc(64)
        mem.ptr(fs_type + self.fl["file_system_type.name"], mem.string("ext4"))
        mem.ptr(self.sb + self.fl["super_block.s_type"], fs_type)
        mem.put(self.sb + self.fl["super_block.s_id"], b"loop3\0")
        mem.ptr(self.head, self.sb + self.fl["super_block.s_list"])
        mem.ptr(self.sb + self.fl["super_block.s_list"], self.head)
        self.keyring = mem.alloc(8 + 8 * self.fl.buckets)
        mem.ptr(self.sb + self.fl["super_block.s_master_keys"], self.keyring)
        self.modes = {XTS: self._mode("AES-256-XTS", "xts(aes)", 64),
                      CTS: self._mode("AES-256-CTS-CBC", "cts(cbc(aes))", 32)}

    def _mode(self, friendly: str, cipher: str, keysize: int) -> int:
        mode = self.mem.alloc(48)
        self.mem.ptr(mode + self.fl["fscrypt_mode.friendly_name"], self.mem.string(friendly))
        self.mem.ptr(mode + self.fl["fscrypt_mode.cipher_str"], self.mem.string(cipher))
        self.mem.u32(mode + self.fl["fscrypt_mode.keysize"], keysize)
        return mode

    def add_key(self, spec_type: int, ref: bytes, raw: bytes = b"", hmac_blob: bytes = None,
                bucket: int = None, size: int = 64, hw_wrapped: bool = False, hmac_driver: str = None) -> int:
        mem = self.mem
        mk = mem.alloc(1024)
        spec = mk + self.fl["fscrypt_master_key.mk_spec"]
        mem.u32(spec + self.fl["fscrypt_key_specifier.type"], spec_type)
        mem.put(spec + self.fl["fscrypt_key_specifier.u"], ref)
        secret = mk + self.fl["fscrypt_master_key.mk_secret"]
        mem.u32(secret + self.fl["fscrypt_master_key_secret.size"], size)
        mem.put(secret + self.fl["fscrypt_master_key_secret.raw"], raw.ljust(64, b"\0"))
        if hw_wrapped:
            mem.put(secret + self.fl["fscrypt_master_key_secret.is_hw_wrapped"], b"\x01")
        if hmac_blob is not None and self.fl.hkdf_inline:
            mem.put(secret + self.fl["fscrypt_master_key_secret.hkdf"], hmac_blob)
        elif hmac_blob is not None:
            shash = make_tfm(mem, "hmac(sha512)", hmac_driver or "hmac(sha512-generic)", hmac_blob)
            mem.ptr(secret + self.fl["fscrypt_master_key_secret.hkdf"] + self.fl["fscrypt_hkdf.hmac_tfm"], shash)
        mem.put(mk + self.fl["fscrypt_master_key.mk_present"], b"\x01")
        inodes = mk + self.fl["fscrypt_master_key.mk_decrypted_inodes"]
        mem.ptr(inodes, inodes)
        mem.ptr(inodes + 8, inodes)
        if bucket is None:
            bucket = fscrypt.expected_bucket(ref.ljust(32, b"\0"), self.fl.buckets)
        slot = self.keyring + self.fl["fscrypt_keyring.key_hashtable"] + 8 * bucket
        mem.ptr(mk + self.fl["fscrypt_master_key.mk_node"], int.from_bytes(self._read(slot, 8), "little"))
        mem.ptr(slot, mk + self.fl["fscrypt_master_key.mk_node"])
        return mk

    def add_inode(self, mk: int, ino: int, mode: int, nonce: bytes, policy: bytes, aes_ctx_keys,
                  backpointer: int = None) -> int:
        """An inode whose transform holds ``aes_ctx_keys`` (64-byte XTS key or 32-byte CTS key)."""
        mem = self.mem
        ci = mem.alloc(136)
        inode = mem.alloc(128)
        mem.u64(inode + self.fl["inode.i_ino"], ino)
        mem.ptr(ci + self.fl["fscrypt_inode_info.ci_inode"], inode)
        mem.ptr(ci + self.fl["fscrypt_inode_info.ci_master_key"], mk if backpointer is None else backpointer)
        mem.ptr(ci + self.fl["fscrypt_inode_info.ci_mode"], self.modes[mode])
        mem.put(ci + self.fl["fscrypt_inode_info.ci_policy"], policy)
        mem.put(ci + self.fl["fscrypt_inode_info.ci_nonce"], nonce)
        if aes_ctx_keys is None:  # a transform whose context holds no AES schedule
            tfm = make_tfm(mem, "xts(aes)", "xts-generic-test", bytes(976))
        elif mode == XTS:
            tfm = make_tfm(mem, "xts(aes)", "xts-aes-ce", xts_ce_ctx(aes_ctx_keys))
        else:
            tfm = make_tfm(mem, "cts(cbc(aes))", "cts(cbc-aes-generic)", aes.kernel_crypto_aes_ctx(aes_ctx_keys))
        mem.ptr(ci + self.fl["fscrypt_inode_info.ci_enc_key"] + self.fl["fscrypt_prepared_key.tfm"], tfm)
        head = mk + self.fl["fscrypt_master_key.mk_decrypted_inodes"]
        link = ci + self.fl["fscrypt_inode_info.ci_master_key_link"]
        last = int.from_bytes(self._read(head + 8, 8), "little")
        mem.ptr(last, link)       # last.next = link
        mem.ptr(link, head)       # link.next = head
        mem.ptr(link + 8, last)
        mem.ptr(head + 8, link)   # head.prev = link
        return ci

    def _read(self, address: int, length: int) -> bytes:
        start = address - Mem.BASE
        return bytes(self.mem.buf[start:start + length])

    def plugin(self, guessed=()) -> "BarePlugin":
        plugin = BarePlugin()
        plugin.reader, plugin.fl, plugin.kl, plugin.guessed = self.mem.reader(), self.fl, KL, list(guessed)
        plugin._super_blocks = lambda: self.head
        return plugin


class BarePlugin(fscrypt.Fscrypt):
    """The plugin without a vol3 context: ``config`` becomes a plain attribute."""

    config = {}

    def __init__(self) -> None:  # noqa: D107 - no vol3 context
        pass


def v1_policy(descriptor: bytes = DESCRIPTOR, flags: int = 2) -> bytes:
    return bytes((fscrypt.POLICY_V1, XTS, CTS, flags)) + descriptor


def v2_policy(identifier: bytes, flags: int = 2) -> bytes:
    return bytes((fscrypt.POLICY_V2, XTS, CTS, flags, 0, 0, 0, 0)) + identifier


def hmac_ctx_blob(master: bytes) -> bytes:
    """v6.7+ crypto/hmac.c ``struct hmac_ctx {hash; pads[]}`` for fscrypt's PRK."""
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(master)
    return struct.pack("<Q", 0xFFFF888800001000) + sha512_export(ipad) + sha512_export(opad)


def v1_file_key_reference(master: bytes, nonce: bytes, keysize: int) -> bytes:
    """Independent v1 derivation: block-wise AES-128 encryption of the master key under the nonce."""
    return b"".join(aes.encrypt_block(nonce, master[i:i + 16]) for i in range(0, keysize, 16))


def v2_file_key_reference(master: bytes, nonce: bytes, keysize: int) -> bytes:
    """Independent v2 derivation through the standard library's hmac (RFC 5869)."""
    prk = hmac.new(bytes(64), master, "sha512").digest()
    return hk.hkdf_expand(prk, b"fscrypt\0\x02" + nonce, keysize)


def v1_image(master=V1_KEY, inode_master=None, inodes=2):
    image = Image()
    mk = image.add_key(fscrypt.KEY_SPEC_DESCRIPTOR, DESCRIPTOR, master)
    for index in range(inodes):
        nonce = bytes([index + 1]) * 16
        mode = XTS if index else CTS
        keysize = 64 if mode == XTS else 32
        image.add_inode(mk, 12 + index, mode, nonce, v1_policy(),
                        v1_file_key_reference(inode_master or master, nonce, keysize))
    return image, mk


def v2_image(master=V2_KEY, identifier=None, inodes=2):
    image = Image()
    identifier = identifier or hk.fscrypt_v2_identifier(master)
    mk = image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, identifier, b"", hmac_ctx_blob(master))
    for index in range(inodes):
        nonce = bytes([0xA0 + index]) * 16
        mode = XTS if index else CTS
        keysize = 64 if mode == XTS else 32
        image.add_inode(mk, 17 + index, mode, nonce, v2_policy(identifier),
                        v2_file_key_reference(master, nonce, keysize))
    return image, mk


# --------------------------------------------------------------------------- derivations


def test_v1_file_key_is_aes128_ecb_of_the_master_under_the_nonce():
    nonce = bytes(range(16))
    derived = fscrypt.derive_v1_file_key(V1_KEY, nonce, 64)
    assert derived == v1_file_key_reference(V1_KEY, nonce, 64)
    assert aes.ecb_decrypt(nonce, derived) == V1_KEY
    assert fscrypt.derive_v1_file_key(V1_KEY, nonce, 32) == derived[:32]


def test_v2_file_key_from_midstates_equals_stdlib_hkdf():
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    state = fscrypt.HkdfState(ipad, opad, "hmac_ctx", "test")
    nonce = bytes(range(16, 32))
    assert fscrypt.derive_v2_file_key(state, nonce, 64) == v2_file_key_reference(V2_KEY, nonce, 64)


def test_aes_keys_of_and_schedule_comparison():
    derived = bytes(range(64))
    assert fscrypt.aes_keys_of("xts(aes)", derived) == [derived[:32], derived[32:]]
    assert fscrypt.aes_keys_of("cts(cbc(aes))", derived[:32]) == [derived[:32]]
    assert fscrypt.aes_keys_of("adiantum(xchacha12,aes)", derived[:32]) is None
    halves = [derived[:32], derived[32:]]
    assert fscrypt.compare_schedules(halves, halves[::-1]) == "match"
    assert fscrypt.compare_schedules(halves, [halves[0]]) == "partial"
    assert fscrypt.compare_schedules(halves, [bytes(32)]) == "mismatch"
    assert fscrypt.compare_schedules(halves, []) == "no-schedule"


def test_hmac_blob_layouts():
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    pads = sha512_export(ipad) + sha512_export(opad)
    assert fscrypt.parse_hmac_blob(hmac_ctx_blob(V2_KEY), "hmac(sha512-avx2)", "little", 8) == (
        ipad, opad, hk.SHA512_LAYOUT_HMAC_CTX)
    assert fscrypt.parse_hmac_blob(pads + bytes(8), "hmac(sha512-generic)", "little", 8) == (
        ipad, opad, hk.SHA512_LAYOUT_HMAC_PADS)
    assert fscrypt.parse_hmac_blob(os.urandom(512), "hmac(sha512-generic)", "little", 8) is None


def test_policy_text():
    assert fscrypt.policy_text(v1_policy()) == "AES-256-XTS/AES-256-CTS PAD_16"
    assert fscrypt.policy_text(bytes((2, 1, 4, 0x02 | 0x08))) == "AES-256-XTS/AES-256-CTS PAD_16|IV_INO_LBLK_64"
    assert fscrypt.policy_text(None) == "?"


# --------------------------------------------------------------------------- walk + proofs


def test_v1_key_proven_by_per_file_schedules():
    image, mk = v1_image()
    (record,) = image.plugin()._collect()
    assert (record.version, record.raw, record.key_ref, record.device, record.fs_type) == (
        "v1", V1_KEY, DESCRIPTOR, "loop3", "ext4")
    assert [c.result for c in record.inodes] == ["match", "match"]
    assert record.status == "oracle:per-file-schedule" and record.proven


def test_v2_key_proven_by_identifier_and_per_file_schedules():
    image, mk = v2_image()
    plugin = image.plugin()
    (record,) = plugin._collect()
    assert record.version == "v2" and not any(record.raw)
    assert (record.hkdf.ipad, record.hkdf.opad) == hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    assert record.hkdf.layout == hk.SHA512_LAYOUT_HMAC_CTX
    assert record.status == "oracle:identifier+per-file-schedule"
    (entry,) = plugin._json_report([record])
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    assert entry["hkdf_prk_midstates"]["ipad_sha512_state_hex"] == struct.pack(">8Q", *ipad).hex()
    assert entry["hkdf_prk_midstates"]["opad_sha512_state_hex"] == struct.pack(">8Q", *opad).hex()
    assert entry["master_key_hex"] is None


def test_v2_identifier_alone_proves_without_inodes():
    image, _mk = v2_image(inodes=0)
    (record,) = image.plugin()._collect()
    assert record.status == "oracle:identifier"


def test_v2_wrong_identifier_is_rejected():
    image, _mk = v2_image(identifier=bytes(range(16)))
    (record,) = image.plugin()._collect()
    assert record.status == "rejected" and "identifier" in record.detail


def test_v1_wrong_key_is_rejected_by_inode_schedules():
    image, _mk = v1_image(inode_master=bytes(64 * [0x11]))
    (record,) = image.plugin()._collect()
    assert [c.result for c in record.inodes] == ["mismatch", "mismatch"]
    assert record.status == "rejected"


def test_v1_without_resident_inodes_is_unverified():
    image, _mk = v1_image(inodes=0)
    (record,) = image.plugin()._collect()
    assert record.status == "unverified" and record.raw == V1_KEY


def test_v1_descriptor_oracle_fires_only_for_the_userspace_convention():
    descriptor = hashlib.sha512(hashlib.sha512(V1_KEY).digest()).digest()[:8]
    image = Image()
    image.add_key(fscrypt.KEY_SPEC_DESCRIPTOR, descriptor, V1_KEY)
    (record,) = image.plugin()._collect()
    assert record.status == "oracle:descriptor"


@pytest.mark.parametrize("builder", [v1_image, v2_image])
def test_guessed_offsets_never_give_a_proven_row(builder):
    image, _mk = builder()
    (record,) = image.plugin(guessed=["fscrypt_master_key.mk_secret"])._collect()
    assert record.status == "unverified" and not record.proven
    assert "guessed offsets" in record.detail


def test_inode_with_a_foreign_backpointer_or_ref_is_not_counted():
    image, mk = v1_image(inodes=0)
    nonce = bytes(16)
    image.add_inode(mk, 40, XTS, nonce, v1_policy(), v1_file_key_reference(V1_KEY, nonce, 64),
                    backpointer=0x1234)
    image.add_inode(mk, 41, XTS, nonce, v1_policy(descriptor=bytes(8)),
                    v1_file_key_reference(V1_KEY, nonce, 64))
    (record,) = image.plugin()._collect()
    assert [c.result for c in record.inodes] == ["invalid:ci_master_key-backpointer", "invalid:policy-key-ref"]
    assert record.status == "unverified"


def test_direct_key_policy_inode_is_skipped():
    image, mk = v1_image(inodes=0)
    image.add_inode(mk, 50, XTS, bytes(16), v1_policy(flags=0x02 | 0x04), bytes(64))
    (record,) = image.plugin()._collect()
    assert record.inodes[0].result.startswith("skipped:no-per-file-key")
    assert record.status == "unverified"


def test_bucket_mismatch_is_reported():
    image = Image()
    image.add_key(fscrypt.KEY_SPEC_DESCRIPTOR, DESCRIPTOR, V1_KEY, bucket=0)
    (record,) = image.plugin()._collect()
    assert "hashes to" in record.detail


def test_row_labels_the_v2_secret_as_wiped():
    image, _mk = v2_image()
    plugin = image.plugin()
    (record,) = plugin._collect()
    row = dict(zip([c[0] for c in plugin._columns()], plugin._row(record)))
    assert row["Policy"] == "v2" and row["Proven"] == "oracle:identifier+per-file-schedule"
    assert "wiped" in row["Secret"] and row["Inodes"] == "2/2" and row["Offsets"] == "isf"
    assert row["Modes"] == "AES-256-XTS/AES-256-CTS PAD_16"


# --------------------------------------------------------------------------- layouts / support


class FakeModule:
    """A vmlinux module whose ISF has only ``types`` (``{name: {member: offset}}``)."""

    def __init__(self, types):
        self.types = types

    def get_type(self, name):
        if name not in self.types:
            raise exceptions.SymbolError(name, "fake", "no %s" % name)
        members = self.types[name]

        def relative_child_offset(member):  # vol3 raises IndexError for a missing member
            if member not in members:
                raise IndexError("Member not present in template: %s" % member)
            return members[member]
        return SimpleNamespace(relative_child_offset=relative_child_offset,
                               members={m: (o, SimpleNamespace(size=32, vol=SimpleNamespace(count=128)))
                                        for m, o in members.items()})


def _isf_types(drop=(), rename=None):
    types = {}
    for key, offset in fscrypt._LP64_DEFAULTS.items():
        type_name, member = key.split(".", 1)
        types.setdefault(type_name, {})[member] = offset
    for name in drop:
        types.pop(name, None)
    if rename:
        types[rename[1]] = types.pop(rename[0])
    return types


def test_layout_from_full_isf_is_supported_and_not_guessed():
    layout = fscrypt.FscryptLayout.from_module(FakeModule(_isf_types()))
    assert layout.supported is None and layout.guessed() == [] and layout.provenance() == "isf"


def test_layout_accepts_pre_6_6_fscrypt_info_name():
    layout = fscrypt.FscryptLayout.from_module(
        FakeModule(_isf_types(rename=("fscrypt_inode_info", "fscrypt_info"))))
    assert layout.guessed() == []


def test_layout_without_types_is_guessed():
    layout = fscrypt.FscryptLayout.from_module(FakeModule(_isf_types(drop=("fscrypt_master_key",))))
    assert "fscrypt_master_key.mk_secret" in layout.guessed()
    assert layout.provenance().startswith("isf; guessed(")


def test_pre_6_1_keyring_is_unsupported_with_an_explicit_status():
    layout = fscrypt.FscryptLayout.from_module(FakeModule(_isf_types(drop=("fscrypt_keyring",))))
    assert layout.supported == "unsupported-pre-6.1-keyring"
    image = Image()
    plugin = image.plugin()
    plugin.fl = fscrypt.FscryptLayout(supported=layout.supported)
    (record,) = plugin._collect()
    assert record.status == "error:unsupported-pre-6.1-keyring" and not record.proven


def test_kernel_without_fs_encryption_has_no_rows():
    types = _isf_types()
    del types["super_block"]["s_master_keys"]
    layout = fscrypt.FscryptLayout.from_module(FakeModule(types))
    assert layout.supported == "no-fs-encryption"
    plugin = Image().plugin()
    plugin.fl = layout
    assert plugin._collect() == []


# --------------------------------------------------------------------------- review fixes


def test_inode_keysize_not_a_multiple_of_16_is_invalid_not_a_crash():
    image, _mk = v1_image(inodes=2)
    image.mem.u32(image.modes[CTS] + FL["fscrypt_mode.keysize"], 20)
    (record,) = image.plugin()._collect()
    assert record.inodes[0].result == "invalid:keysize-20-not-a-multiple-of-16"
    assert record.inodes[1].result == "match" and record.status == "oracle:per-file-schedule"


def test_any_inode_exception_becomes_an_error_result(monkeypatch):
    image, _mk = v1_image(inodes=1)

    def boom(*_args):
        raise ValueError("corrupt")
    monkeypatch.setattr(fscrypt, "derive_v1_file_key", boom)
    (record,) = image.plugin()._collect()
    assert record.inodes[0].result == "error:ValueError" and record.status == "unverified"


@pytest.mark.parametrize("builder,kwargs", [(v1_image, {"inode_master": bytes([0x11]) * 64}),
                                            (v2_image, {"identifier": bytes(range(16))})])
def test_contradiction_on_guessed_offsets_is_unverified_not_rejected(builder, kwargs):
    image, _mk = builder(**kwargs)
    (record,) = image.plugin(guessed=["fscrypt_master_key.mk_secret"])._collect()
    assert record.status == "unverified" and "contradicts on guessed offsets" in record.detail


def _layout_6_16(**changes):
    """v6.16 secret ``{hkdf; bool is_hw_wrapped; u32 size; u8 bytes[128]}`` (later members move)."""
    layout = fscrypt.FscryptLayout()
    layout.offsets.update({"fscrypt_master_key_secret.is_hw_wrapped": 8, "fscrypt_master_key_secret.size": 12,
                           "fscrypt_master_key_secret.raw": 16, "fscrypt_master_key.mk_spec": 232,
                           "fscrypt_master_key.mk_decrypted_inodes": 280, "fscrypt_master_key.mk_present": 900})
    layout.offsets.update(changes)
    return layout


def test_layout_6_16_reads_bytes_alias_and_hw_wrapped_flag():
    types = _isf_types()
    secret = types["fscrypt_master_key_secret"]
    secret["bytes"] = secret.pop("raw")
    secret["is_hw_wrapped"] = 8
    layout = fscrypt.FscryptLayout.from_module(FakeModule(types))
    assert layout.guessed() == []
    assert layout.offsets["fscrypt_master_key_secret.is_hw_wrapped"] == 8
    assert "fscrypt_master_key_secret.is_hw_wrapped" not in fscrypt.FscryptLayout().offsets  # never guessed


def test_6_16_secret_up_to_128_bytes_is_read():
    image = Image(_layout_6_16())
    long_key = bytes(range(100))
    image.add_key(fscrypt.KEY_SPEC_DESCRIPTOR, DESCRIPTOR, long_key, size=100)
    (record,) = image.plugin()._collect()
    assert record.secret_size == 100 and record.raw == long_key


def test_hw_wrapped_v2_identifier_uses_context_8():
    image = Image(_layout_6_16())
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    state = fscrypt.HkdfState(ipad, opad, "hmac_ctx", "test")
    identifier = fscrypt.identifier_from_state(state, hk.HKDF_CONTEXT_KEY_IDENTIFIER_FOR_HW_WRAPPED_KEY)
    image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, identifier, b"", hmac_ctx_blob(V2_KEY), hw_wrapped=True)
    (record,) = image.plugin()._collect()
    assert record.hw_wrapped and record.status == "oracle:identifier"


def test_hw_wrapped_identifier_mismatch_is_unverified_never_rejected():
    image = Image(_layout_6_16())
    image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, hk.fscrypt_v2_identifier(V2_KEY), b"", hmac_ctx_blob(V2_KEY),
                  hw_wrapped=True)  # context-1 identifier on a hw-wrapped key: no match at context 8
    (record,) = image.plugin()._collect()
    assert record.status == "unverified" and "hardware-wrapped" in record.detail


def test_masked_super_blocks_head_is_not_walked_as_a_superblock():
    image, _mk = v1_image()
    reader = image.mem.reader()
    canonical = 0xFFFF000000000000
    assert kernel_common.is_list_head(image.head | canonical, image.head)

    class Canonical(dmcrypt.SafeReader):  # memory holds canonical pointers, vol3 hands out masked ones
        def read(self, address, length):
            return reader.read(address & ((1 << 48) - 1) if address else address, length)

        def ptr(self, address):
            value = super().ptr(address)
            return value | canonical if value else value
    sbs = list(fscrypt.iter_superblocks(Canonical(reader.layer, 8, "little"), FL, image.head))
    assert sbs == [(image.sb | canonical) - FL["super_block.s_list"]]


def test_node_reachable_from_every_bucket_is_yielded_once():
    image = Image()
    mk = image.add_key(fscrypt.KEY_SPEC_DESCRIPTOR, DESCRIPTOR, V1_KEY, bucket=0)
    for bucket in range(1, FL.buckets):
        image.mem.ptr(image.keyring + FL["fscrypt_keyring.key_hashtable"] + 8 * bucket,
                      mk + FL["fscrypt_master_key.mk_node"])
    assert len(image.plugin()._collect()) == 1


def test_partial_schedule_match_is_noted_and_not_counted():
    image, mk = v1_image(inodes=0)
    nonce = bytes(16)
    derived = v1_file_key_reference(V1_KEY, nonce, 64)
    image.add_inode(mk, 60, XTS, nonce, v1_policy(), derived[:32] + bytes([0x22]) * 32)
    (record,) = image.plugin()._collect()
    assert record.inodes[0].result == "partial" and record.status == "unverified"
    assert "only part of the derived key" in record.detail


def test_inode_transform_without_schedules_is_no_schedule():
    image, mk = v1_image(inodes=0)
    image.add_inode(mk, 61, XTS, bytes(16), v1_policy(), None)
    (record,) = image.plugin()._collect()
    assert record.inodes[0].result == "no-schedule" and record.status == "unverified"


def test_read_hkdf_state_hmac_pads_and_lib_drivers():
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    for driver, blob, layout in (
            ("hmac(sha512-generic)", sha512_export(ipad) + sha512_export(opad), hk.SHA512_LAYOUT_HMAC_PADS),
            ("hmac-sha512-lib", struct.pack("<8Q", *ipad) + struct.pack("<8Q", *opad),
             hk.SHA512_LAYOUT_HMAC_SHA512_KEY)):
        image = Image()
        mk = image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, hk.fscrypt_v2_identifier(V2_KEY), b"", blob,
                           hmac_driver=driver)
        state, why = fscrypt.read_hkdf_state(image.mem.reader(), KL, FL, mk)
        assert (state.ipad, state.opad, state.layout, state.driver, why) == (ipad, opad, layout, driver, "")


def test_read_hkdf_state_inline_6_18_struct():
    layout = _layout_6_16(**{"fscrypt_master_key_secret.size": 128, "fscrypt_master_key_secret.raw": 132,
                             "fscrypt_master_key.mk_spec": 344, "fscrypt_master_key.mk_decrypted_inodes": 400})
    layout.offsets.pop("fscrypt_master_key_secret.is_hw_wrapped")
    layout.hkdf_inline = True  # v6.18: struct hmac_sha512_key hkdf (128 B) heads the secret
    image = Image(layout)
    ipad, opad = hk.fscrypt_v2_hkdf_midstates(V2_KEY)
    image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, hk.fscrypt_v2_identifier(V2_KEY), b"",
                  struct.pack("<8Q", *ipad) + struct.pack("<8Q", *opad), size=0)
    (record,) = image.plugin()._collect()
    assert (record.hkdf.layout, record.hkdf.driver) == (hk.SHA512_LAYOUT_HMAC_SHA512_KEY, "inline")
    assert record.status == "oracle:identifier"


def test_all_zero_midstates_are_no_state_and_zero_identifier_is_rejected():
    image = Image()
    image.add_key(fscrypt.KEY_SPEC_IDENTIFIER, hk.fscrypt_v2_identifier(V2_KEY), b"", bytes(424))
    (record,) = image.plugin()._collect()
    assert record.hkdf is None and record.status == "unverified" and "no exported sha512" in record.detail
    image2, _mk = v2_image(identifier=bytes(16), inodes=0)
    (record2,) = image2.plugin()._collect()
    assert record2.status == "rejected"


@pytest.mark.parametrize("size", [0, 16])
def test_zero_or_short_secret_size_is_unverified(size):
    image, _mk = v1_image(inodes=1)
    image.mem.u32(_mk + FL["fscrypt_master_key.mk_secret"] + FL["fscrypt_master_key_secret.size"], size)
    (record,) = image.plugin()._collect()
    assert record.status == "unverified" and record.secret_size == size
    assert record.inodes[0].result == "skipped:no-secret"


def test_cyclic_decrypted_inode_list_terminates():
    image, mk = v1_image(inodes=2)
    head = mk + FL["fscrypt_master_key.mk_decrypted_inodes"]
    first_link = int.from_bytes(image._read(head, 8), "little")
    image.mem.ptr(first_link, first_link)  # first inode's link points at itself: a cycle off the head
    (record,) = image.plugin()._collect()
    assert len(record.inodes) == 1
    ring = [image.add_inode(mk, 70 + i, CTS, bytes(16), v1_policy(), bytes(32)) for i in range(3)]
    links = [ci + FL["fscrypt_inode_info.ci_master_key_link"] for ci in ring]
    image.mem.ptr(links[-1], links[0])  # a three-node ring that never returns to the head
    assert len(list(kernel_common.iter_list(image.mem.reader(), links[0], limit=fscrypt.MAX_INODES))) == 2


# --------------------------------------------------------------------------- real captures (gated)

CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
X86_STEMS = ("ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic",
             "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic")


def _stock_vol():
    configured = os.environ.get("MEMDIVER_VOL3_BIN", "")
    found = configured or shutil.which("vol") or str(Path(sys.executable).with_name("vol"))
    return [sys.executable, found] if found.endswith(".py") else [found]


def _alt_vol():
    alt = os.environ.get("MEMDIVER_VOL3_ALT_VOL_PY", "")
    return [sys.executable, alt] if alt and Path(alt).is_file() else None


VOL_TREES = {"stock": _stock_vol, "alt": _alt_vol}


@pytest.mark.parametrize("tree", sorted(VOL_TREES))
@pytest.mark.parametrize("stem", X86_STEMS)
def test_real_x86_capture(tmp_path, stem, tree):
    """Both keys found; v1 KeyHex and v2 midstates equal ground truth; both proven."""
    sidecar = CAPTURE_DIR / (stem + ".secrets.json")
    vol = VOL_TREES[tree]()
    if not ((CAPTURE_DIR / (stem + ".lime")).is_file() and sidecar.is_file()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture not present")
    if vol is None or not Path(vol[-1]).is_file():
        pytest.skip("vol tree %r not present (MEMDIVER_VOL3_BIN / MEMDIVER_VOL3_ALT_VOL_PY)" % tree)
    symbols = tmp_path / "sym" / "linux"
    symbols.mkdir(parents=True)
    (symbols / (stem + ".json")).symlink_to(CAPTURE_DIR / (stem + ".isf.json"))
    (tmp_path / "cache").mkdir()
    command = vol + ["-q", "-r", "json", "-s", str(tmp_path / "sym"), "-p", str(REPO / "vol3plugins"),
                     "-f", str(CAPTURE_DIR / (stem + ".lime")), "--cache-path", str(tmp_path / "cache"),
                     "-o", str(tmp_path), "linux.fscrypt", "--export", "json"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path), timeout=1800)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = {row["KeyRef"]: row for row in json.loads(result.stdout)}
    report = {entry["key_ref_hex"]: entry for entry in json.loads((tmp_path / "fscrypt.json").read_text())}
    truth = json.loads(sidecar.read_text())["fscrypt"]
    assert {t["policy_version"] for t in truth} == {"v1", "v2"}
    for entry in truth:
        ref, master = entry["key_ref_hex"], bytes.fromhex(entry["master_key_hex"])
        row = rows[ref]
        assert (row["Policy"], row["Device"], row["FsType"], row["Offsets"]) == (
            entry["policy_version"], Path(entry["loop_device"]).name, "ext4", "isf")
        assert row["Modes"] == "%s/%s %s" % (entry["contents_mode"], entry["filenames_mode"], entry["flags"])
        if entry["policy_version"] == "v1":
            assert row["KeyHex"] == entry["master_key_hex"]
            assert row["Proven"] == "oracle:per-file-schedule"
        else:
            ipad, opad = hk.fscrypt_v2_hkdf_midstates(master)
            midstates = report[ref]["hkdf_prk_midstates"]
            assert midstates["ipad_sha512_state_hex"] == struct.pack(">8Q", *ipad).hex()
            assert midstates["opad_sha512_state_hex"] == struct.pack(">8Q", *opad).hex()
            assert row["Proven"] == "oracle:identifier+per-file-schedule"
        matched, checked = map(int, row["Inodes"].split("/"))
        assert checked > 0 and matched == checked
