"""``linux.fscrypt`` -- fscrypt master keys of every mounted filesystem, proven from memory.

Walk (v6.1+)
------------
``super_blocks`` -> every ``super_block`` with a non-NULL ``s_master_keys`` (``struct
fscrypt_keyring``, fs/crypto/keyring.c) -> ``key_hashtable[]`` buckets -> ``struct
fscrypt_master_key`` (``mk_node``).  Keys added with ``FS_IOC_ADD_ENCRYPTION_KEY`` live here,
*not* in ``key_serial_tree`` (that is ``linux.keyring``).  For each key the plugin also walks
``mk_decrypted_inodes`` -> ``struct fscrypt_inode_info`` (``fscrypt_info`` before v6.6) via
``ci_master_key_link``, i.e. the inodes whose per-file key was derived from it.  fscrypt is
never a module (``CONFIG_FS_ENCRYPTION`` is a bool), so every offset comes from the vmlinux
ISF; an LP64 v6.8 table is only the announced fallback, and a key read through any guessed
offset is never labelled proven.  Before v6.1 ``s_master_keys`` is a ``struct key *`` keyring:
those superblocks are listed with ``error:unsupported-pre-6.1-keyring``, never decoded.

Secrets
-------
* **v1** (``mk_spec.type == DESCRIPTOR``): ``mk_secret.raw[:size]`` is the raw master key
  (v6.16 renamed the member ``bytes[]`` and widened it to 128 bytes; both are read).
* **v2** (``IDENTIFIER``): the raw key is zeroed right after ``fscrypt_init_hkdf()``; what is
  left is the HMAC-SHA512 transform keyed with the HKDF PRK (``mk_secret.hkdf.hmac_tfm``),
  i.e. the SHA-512 ipad/opad midstates (``secrets.hkdf_midstate`` layouts ``hmac_ctx``,
  ``hmac_pads`` and ``hmac_sha512_key``).  They are enough to derive every key the kernel
  derives, but the master key itself is gone; ``--export json`` writes the midstates.

Kernel versions
---------------
Proven on real images: x86_64 v6.8 (``hmac_ctx`` pads, both policy versions, 4- and 5-level
paging).  Implemented from the kernel sources but exercised on synthetic memory only: the
v6.6 ``fscrypt_info`` name, the <= v6.6 ``hmac_pads`` layout, the v6.16 ``bytes[]`` /
``is_hw_wrapped`` secret (hardware-wrapped keys: identifier context 8; a mismatch there is
``unverified``, never ``rejected``), the v6.17 ``hmac-sha512-lib`` driver and the v6.18
``struct hmac_sha512_key`` embedded in the secret.

Proof (``Proven`` is ``oracle:<kind>`` | ``unverified`` | ``rejected`` | ``error:<why>``)
------------------------------------------------------------------------------------------
* ``identifier`` (v2): HKDF-Expand(PRK, ``"fscrypt\\0" || 1``, 16) recomputed from the
  midstates equals ``mk_spec.u.identifier`` -- the value the kernel computed itself.
* ``per-file-schedule`` (v1 and v2): for each decrypted inode the per-file key is re-derived --
  v1 ``AES-128-ECB(key = ci_nonce, raw[:mode keysize])`` (fs/crypto/keysetup_v1.c
  ``derive_key_aes``), v2 ``HKDF-Expand(PRK, "fscrypt\\0" || 2 || ci_nonce, keysize)`` -- and
  its AES keys (``xts(aes)``: both halves, ``cts(cbc(aes))``: the whole key) must be the AES
  key schedules inside that inode's ``ci_enc_key`` transform (``dmcrypt.collect_schedules``).
  An inode that cannot be checked (corrupt mode, any read/derivation failure) is reported as
  ``invalid:``/``error:`` and never stops the plugin.
* ``descriptor`` (v1, extra): ``SHA-512(SHA-512(raw))[:8]`` equals the descriptor.  The kernel
  does not enforce this convention (e4crypt/fscryptctl/fscrypt follow it), so it only fires
  when user space chose the descriptor that way.
* Any contradicting check (identifier mismatch, an inode whose schedules match none of the
  derived keys) gives ``rejected``; on guessed offsets both a contradiction and a passed
  oracle are ``unverified``.
"""

import json
import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import dmcrypt, keyring
from .kernel_common import (IsfLayout, SafeReader, isf_member_template, isf_offset, isf_type,
                            iter_list, kernel_reader, symbol_address)
from .secrets import aes
from .secrets import hkdf_midstate as hk

vollog = logging.getLogger(__name__)

MAX_SUPERBLOCKS = 1 << 14
MAX_BUCKET_CHAIN = 1024
MAX_INODES = 256  # decrypted inodes checked per master key
FSCRYPT_MAX_KEY_SIZE = 64  # largest raw software key / per-file key
FSCRYPT_MAX_ANY_KEY_SIZE = 128  # v6.16+ mk_secret.bytes[] (hardware-wrapped keys are longer)
AES_BLOCK = 16
FSCRYPT_FILE_NONCE_SIZE = 16
KEY_SPEC_DESCRIPTOR, KEY_SPEC_IDENTIFIER = 1, 2
POLICY_V1, POLICY_V2 = 0, 2  # union fscrypt_policy.version
HMAC_CTX_READ = 1024  # bytes of the hmac(sha512) context read (pointer + 2 x 209-byte pads)

MODE_NAMES = {1: "AES-256-XTS", 4: "AES-256-CTS", 5: "AES-128-CBC", 6: "AES-128-CTS",
              7: "SM4-XTS", 8: "SM4-CTS", 9: "Adiantum", 10: "AES-256-HCTR2"}
PAD_NAMES = ("PAD_4", "PAD_8", "PAD_16", "PAD_32")
FLAG_NAMES = ((0x04, "DIRECT_KEY"), (0x08, "IV_INO_LBLK_64"), (0x10, "IV_INO_LBLK_32"))
PER_FILE_KEY_FLAGS = 0x04 | 0x08 | 0x10  # these policies do not use a per-file key

PROVEN_PREFIX = "oracle:"
UNVERIFIED, REJECTED = "unverified", "rejected"

# ISF type name candidates: struct fscrypt_info was renamed fscrypt_inode_info in v6.6.
TYPE_ALIASES = {"fscrypt_inode_info": ("fscrypt_inode_info", "fscrypt_info")}
# ISF member name candidates: v6.16 renamed mk_secret.raw[64] to bytes[FSCRYPT_MAX_ANY_KEY_SIZE].
MEMBER_ALIASES = {"fscrypt_master_key_secret.raw": ("raw", "bytes")}
# Members read only when the ISF has them (never guessed): v6.16+ hardware-wrapped flag.
OPTIONAL_KEYS = ("fscrypt_master_key_secret.is_hw_wrapped",)

_LP64_DEFAULTS = {  # x86_64 v6.8.0-136 (ISF of the reference capture); used only when the ISF lacks one
    "super_block.s_list": 0, "super_block.s_type": 40, "super_block.s_master_keys": 184,
    "super_block.s_id": 960, "file_system_type.name": 0,
    "fscrypt_keyring.key_hashtable": 8,
    "fscrypt_master_key.mk_node": 0, "fscrypt_master_key.mk_secret": 80,  # nosec B105 -- struct offset
    "fscrypt_master_key.mk_spec": 160, "fscrypt_master_key.mk_decrypted_inodes": 208,
    "fscrypt_master_key.mk_present": 777,
    "fscrypt_master_key_secret.hkdf": 0, "fscrypt_master_key_secret.size": 8,
    "fscrypt_master_key_secret.raw": 12, "fscrypt_hkdf.hmac_tfm": 0,
    "fscrypt_key_specifier.type": 0, "fscrypt_key_specifier.u": 8,
    "fscrypt_inode_info.ci_enc_key": 0, "fscrypt_inode_info.ci_mode": 24,
    "fscrypt_inode_info.ci_inode": 32, "fscrypt_inode_info.ci_master_key": 40,
    "fscrypt_inode_info.ci_master_key_link": 48, "fscrypt_inode_info.ci_policy": 89,
    "fscrypt_inode_info.ci_nonce": 113, "fscrypt_prepared_key.tfm": 0,
    "fscrypt_mode.friendly_name": 0, "fscrypt_mode.cipher_str": 8, "fscrypt_mode.keysize": 16,
    "inode.i_ino": 80, "crypto_shash.base": 8,
}
_DEFAULT_BUCKETS = 128
_DEFAULT_S_ID_SIZE = 32


# --------------------------------------------------------------------------- layout


@dataclass
class FscryptLayout(IsfLayout):
    """Offsets (``"type.member" -> offset``) with provenance ``isf`` | ``default`` per key.

    ``supported`` is ``None`` when the walk can run, else why not (``unsupported-pre-6.1-keyring``
    or ``no-fs-encryption``).  A bare ``FscryptLayout()`` (unit tests) counts as ISF-backed.
    """

    offsets: Dict[str, int] = field(default_factory=lambda: dict(_LP64_DEFAULTS))
    buckets: int = _DEFAULT_BUCKETS
    s_id_size: int = _DEFAULT_S_ID_SIZE
    hkdf_inline: bool = False  # v6.18+: struct hmac_sha512_key embedded in mk_secret.hkdf
    supported: Optional[str] = None

    def guessed(self) -> List[str]:
        return self.defaulted()

    def provenance(self, extra_guessed: Sequence[str] = ()) -> str:
        guessed = sorted(set(self.guessed()) | set(extra_guessed))
        return "isf" if not guessed else "isf; guessed(%d): %s" % (len(guessed), ", ".join(guessed))

    @classmethod
    def from_module(cls, module: Any) -> "FscryptLayout":
        layout = cls()
        layout.resolve(lambda key: _isf_offset(module, key, *MEMBER_ALIASES.get(key, ())))
        for key in OPTIONAL_KEYS:
            offset = _isf_offset(module, key)
            if offset is not None:
                layout.offsets[key], layout.sources[key] = offset, "isf"
        layout._fill_sizes(module)
        layout.supported = _support(module, layout)
        return layout

    def _fill_sizes(self, module: Any) -> None:
        template = _member_template(module, "fscrypt_keyring", "key_hashtable")
        count = getattr(getattr(template, "vol", None), "count", None)
        if isinstance(count, int) and 0 < count <= 1 << 16:
            self.buckets = count
        s_id = _member_template(module, "super_block", "s_id")
        size = getattr(s_id, "size", None)
        if isinstance(size, int) and 0 < size <= 256:
            self.s_id_size = size
        hkdf = _member_template(module, "fscrypt_master_key_secret", "hkdf")
        hkdf_type = str(getattr(getattr(hkdf, "vol", None), "type_name", "")).split("!")[-1]
        if hkdf_type == "hmac_sha512_key":
            self.hkdf_inline = True
            self.sources.pop("fscrypt_hkdf.hmac_tfm", None)


def _type(module: Any, type_name: str) -> Optional[Any]:
    return isf_type(module, TYPE_ALIASES.get(type_name, (type_name,)))


def _isf_offset(module: Any, key: str, *members: str) -> Optional[int]:
    """Offset of ``key`` (``"type.member"``), else of the first renamed member alias the ISF has."""
    type_name, member = key.split(".", 1)
    return isf_offset(module, TYPE_ALIASES.get(type_name, (type_name,)), *(members or (member,)))


def _member_template(module: Any, type_name: str, member: str) -> Optional[Any]:
    return isf_member_template(module, TYPE_ALIASES.get(type_name, (type_name,)), member)


def _support(module: Any, layout: FscryptLayout) -> Optional[str]:
    if layout.sources.get("super_block.s_master_keys") != "isf":
        return "no-fs-encryption"  # super_block has no s_master_keys: CONFIG_FS_ENCRYPTION=n
    if _type(module, "fscrypt_keyring") is None:
        return "unsupported-pre-6.1-keyring"  # s_master_keys is a struct key * keyring
    return None


# --------------------------------------------------------------------------- records


@dataclass
class HkdfState:
    ipad: Tuple[int, ...]
    opad: Tuple[int, ...]
    layout: str
    driver: str


@dataclass
class InodeCheck:
    address: int
    ino: Optional[int] = None
    mode: str = "?"
    policy: Optional[bytes] = None
    result: str = "unread"  # match | partial | mismatch | no-schedule | skipped:<why> | invalid:<why>
    driver: str = ""


@dataclass
class MasterKey:
    address: int
    superblock: int
    device: str
    fs_type: str
    bucket: int
    spec_type: Optional[int] = None
    key_ref: bytes = b""
    secret_size: int = 0
    raw: bytes = b""
    present: Optional[bool] = None
    hkdf: Optional[HkdfState] = None
    hkdf_why: str = ""
    hw_wrapped: bool = False  # v6.16+ is_hw_wrapped: identifier uses HKDF context 8
    inodes: List[InodeCheck] = field(default_factory=list)
    status: str = UNVERIFIED
    detail: str = ""

    @property
    def version(self) -> str:
        return {KEY_SPEC_DESCRIPTOR: "v1", KEY_SPEC_IDENTIFIER: "v2"}.get(self.spec_type, "?")

    @property
    def proven(self) -> bool:
        return self.status.startswith(PROVEN_PREFIX)


# --------------------------------------------------------------------------- walks


def iter_superblocks(reader: SafeReader, fl: FscryptLayout, super_blocks: int) -> Iterator[int]:
    return iter_list(reader, super_blocks, fl["super_block.s_list"], MAX_SUPERBLOCKS)


def superblock_names(reader: SafeReader, fl: FscryptLayout, sb: int) -> Tuple[str, str]:
    device = reader.inline_string(sb + fl["super_block.s_id"], fl.s_id_size) or "?"
    fs_type = reader.ptr(sb + fl["super_block.s_type"])
    name = reader.cstring(reader.ptr(fs_type + fl["file_system_type.name"])) if fs_type else None
    return device, name or "?"


def iter_master_keys(reader: SafeReader, fl: FscryptLayout, fs_keyring: int) -> Iterator[Tuple[int, int]]:
    """``(bucket, fscrypt_master_key address)`` of every key in the keyring's hash table."""
    pointer = reader.pointer_size
    table = fs_keyring + fl["fscrypt_keyring.key_hashtable"]
    seen: set = set()  # shared by all buckets: a node reachable from several is yielded once
    for bucket in range(fl.buckets):
        node, chain = reader.ptr(table + bucket * pointer), 0
        while node and node not in seen and chain < MAX_BUCKET_CHAIN:
            chain += 1
            seen.add(node)
            yield bucket, node - fl["fscrypt_master_key.mk_node"]
            node = reader.ptr(node)  # hlist_node.next


def expected_bucket(key_ref_union: bytes, buckets: int, pointer_size: int = 8) -> Optional[int]:
    """fs/crypto/keyring.c ``fscrypt_mk_hash_bucket()``: first ``unsigned long`` of ``u`` mod size."""
    if len(key_ref_union) < pointer_size or buckets <= 0:
        return None
    return int.from_bytes(key_ref_union[:pointer_size], "little") % buckets


def read_master_key(reader: SafeReader, fl: FscryptLayout, mk: int, sb: int, device: str,
                    fs_type: str, bucket: int) -> Optional[MasterKey]:
    """Decode one ``fscrypt_master_key``; None when it is not plausibly one (bad spec type)."""
    spec = mk + fl["fscrypt_master_key.mk_spec"]
    spec_type = reader.u32(spec + fl["fscrypt_key_specifier.type"])
    union = reader.read(spec + fl["fscrypt_key_specifier.u"], 32) or b""
    if spec_type not in (KEY_SPEC_DESCRIPTOR, KEY_SPEC_IDENTIFIER) or len(union) < 16:
        return None
    secret = mk + fl["fscrypt_master_key.mk_secret"]
    size = reader.u32(secret + fl["fscrypt_master_key_secret.size"]) or 0
    size = size if 0 < size <= FSCRYPT_MAX_ANY_KEY_SIZE else 0
    raw = reader.read(secret + fl["fscrypt_master_key_secret.raw"], size) if size else b""
    present = reader.u8(mk + fl["fscrypt_master_key.mk_present"])
    hw_offset = fl.offsets.get("fscrypt_master_key_secret.is_hw_wrapped")
    hw_wrapped = reader.u8(secret + hw_offset) if hw_offset is not None else None
    record = MasterKey(address=mk, superblock=sb, device=device, fs_type=fs_type, bucket=bucket,
                       spec_type=spec_type, secret_size=size,
                       key_ref=union[:8] if spec_type == KEY_SPEC_DESCRIPTOR else union[:16],
                       raw=raw or b"", present=None if present is None else bool(present),
                       hw_wrapped=bool(hw_wrapped))
    wanted = expected_bucket(union, fl.buckets, reader.pointer_size)
    if wanted is not None and wanted != bucket:
        record.detail = "found in bucket %d, its key specifier hashes to %d" % (bucket, wanted)
    return record


def iter_decrypted_inodes(reader: SafeReader, fl: FscryptLayout, mk: int) -> Iterator[int]:
    head = mk + fl["fscrypt_master_key.mk_decrypted_inodes"]
    return iter_list(reader, head, fl["fscrypt_inode_info.ci_master_key_link"], MAX_INODES)


# --------------------------------------------------------------------------- v2 HKDF state


def _hmac_layouts(driver: str) -> Tuple[str, ...]:
    if driver.endswith("-lib"):  # v6.17 crypto/sha512.c hmac-sha512-lib: bare struct hmac_sha512_key
        return (hk.SHA512_LAYOUT_HMAC_SHA512_KEY,)
    return (hk.SHA512_LAYOUT_HMAC_CTX, hk.SHA512_LAYOUT_HMAC_PADS)


def parse_hmac_blob(blob: bytes, driver: str, byteorder: str,
                    pointer_size: int) -> Optional[Tuple[Tuple[int, ...], Tuple[int, ...], str]]:
    """``(ipad, opad, layout)`` from an ``hmac(sha512)`` context, first layout that validates."""
    for layout in _hmac_layouts(driver):
        try:
            ipad, opad = hk.parse_sha512_state(blob, layout, byteorder, pointer_size=pointer_size)
        except ValueError:
            continue
        return ipad, opad, layout
    return None


def read_hkdf_state(reader: SafeReader, kl: dmcrypt.KernelLayout, fl: FscryptLayout,
                    mk: int) -> Tuple[Optional[HkdfState], str]:
    """The HKDF PRK's HMAC-SHA512 midstates of a v2 key, or ``(None, why)``."""
    hkdf = mk + fl["fscrypt_master_key.mk_secret"] + fl["fscrypt_master_key_secret.hkdf"]
    if fl.hkdf_inline:
        blob = reader.read(hkdf, 128)
        if not blob or not any(blob):
            return None, "inline hmac_sha512_key unreadable or zero"
        ipad, opad = hk.parse_sha512_state(blob, hk.SHA512_LAYOUT_HMAC_SHA512_KEY, reader.byteorder)
        return HkdfState(ipad, opad, hk.SHA512_LAYOUT_HMAC_SHA512_KEY, "inline"), ""
    shash = reader.ptr(hkdf + fl["fscrypt_hkdf.hmac_tfm"])
    if not shash:
        return None, "hkdf.hmac_tfm is NULL (key removed or HKDF never set up)"
    tfm = dmcrypt.read_tfm(reader, kl, shash + fl["crypto_shash.base"])
    if tfm is None or tfm.cra_name != "hmac(sha512)":
        return None, "hkdf.hmac_tfm is not an hmac(sha512) transform (%s)" % (tfm.cra_name if tfm else "unreadable")
    blob = reader.read(tfm.ctx, min(tfm.ctx_size or HMAC_CTX_READ, HMAC_CTX_READ)) or b""
    parsed = parse_hmac_blob(blob, tfm.driver, reader.byteorder, reader.pointer_size)
    if parsed is None:
        return None, "%s context holds no exported sha512 ipad/opad state" % tfm.driver
    return HkdfState(parsed[0], parsed[1], parsed[2], tfm.driver), ""


# --------------------------------------------------------------------------- per-file keys


def derive_v1_file_key(raw: bytes, nonce: bytes, keysize: int) -> bytes:
    """fs/crypto/keysetup_v1.c ``derive_key_aes``: AES-128-ECB(key = nonce) of ``raw[:keysize]``."""
    return aes.ecb_encrypt(nonce, raw[:keysize])


def derive_v2_file_key(state: HkdfState, nonce: bytes, keysize: int) -> bytes:
    """fs/crypto/keysetup.c: HKDF-Expand(PRK, ``"fscrypt\\0" || PER_FILE_ENC_KEY || nonce``)."""
    info = hk.fscrypt_hkdf_info(hk.HKDF_CONTEXT_PER_FILE_ENC_KEY, nonce)
    return hk.hkdf_expand_sha512_from_midstates(state.ipad, state.opad, info, keysize)


def aes_keys_of(cipher_str: str, derived: bytes) -> Optional[List[bytes]]:
    """The AES keys the crypto API keeps for ``cipher_str`` set with ``derived``; None if not AES."""
    if cipher_str == "xts(aes)" and len(derived) in (32, 48, 64):
        half = len(derived) // 2
        return [derived[:half], derived[half:]]
    if cipher_str == "cts(cbc(aes))" and len(derived) in (16, 24, 32):
        return [derived]
    return None


def compare_schedules(expected: Sequence[bytes], found: Sequence[bytes]) -> str:
    if not found:
        return "no-schedule"
    hits = sum(1 for key in expected if key in found)
    if hits == len(expected):
        return "match"
    return "partial" if hits else "mismatch"


def policy_text(policy: Optional[bytes]) -> str:
    if not policy or len(policy) < 4:
        return "?"
    flags = policy[3]
    names = [PAD_NAMES[flags & 3]] + [name for bit, name in FLAG_NAMES if flags & bit]
    return "%s/%s %s" % (MODE_NAMES.get(policy[1], "mode%d" % policy[1]),
                         MODE_NAMES.get(policy[2], "mode%d" % policy[2]), "|".join(names))


def _policy_ref_ok(policy: bytes, record: MasterKey) -> bool:
    """The inode's own policy names this master key (v1 descriptor @4, v2 identifier @8)."""
    if record.spec_type == KEY_SPEC_DESCRIPTOR:
        return policy[0] == POLICY_V1 and policy[4:12] == record.key_ref
    return policy[0] == POLICY_V2 and policy[8:24] == record.key_ref


def check_inode(reader: SafeReader, kl: dmcrypt.KernelLayout, fl: FscryptLayout,
                record: MasterKey, ci: int) -> InodeCheck:
    """Re-derive one inode's per-file key and compare it with the schedules in its transform."""
    check = InodeCheck(address=ci)
    if reader.ptr(ci + fl["fscrypt_inode_info.ci_master_key"]) != record.address:
        check.result = "invalid:ci_master_key-backpointer"
        return check
    inode = reader.ptr(ci + fl["fscrypt_inode_info.ci_inode"])
    check.ino = reader.u64(inode + fl["inode.i_ino"]) if inode else None
    check.policy = reader.read(ci + fl["fscrypt_inode_info.ci_policy"], 24)
    mode = reader.ptr(ci + fl["fscrypt_inode_info.ci_mode"])
    keysize = reader.u32(mode + fl["fscrypt_mode.keysize"]) if mode else None
    cipher_str = reader.cstring(reader.ptr(mode + fl["fscrypt_mode.cipher_str"])) if mode else None
    check.mode = (reader.cstring(reader.ptr(mode + fl["fscrypt_mode.friendly_name"])) if mode else None) or "?"
    nonce = reader.read(ci + fl["fscrypt_inode_info.ci_nonce"], FSCRYPT_FILE_NONCE_SIZE)
    if not check.policy or not _policy_ref_ok(check.policy, record):
        check.result = "invalid:policy-key-ref"
    elif check.policy[3] & PER_FILE_KEY_FLAGS:
        check.result = "skipped:no-per-file-key(%s)" % policy_text(check.policy).split(" ", 1)[-1]
    elif not keysize or not cipher_str or nonce is None or not 0 < keysize <= FSCRYPT_MAX_KEY_SIZE:
        check.result = "invalid:mode-or-nonce-unreadable"
    elif keysize % AES_BLOCK:
        check.result = "invalid:keysize-%d-not-a-multiple-of-16" % keysize
    else:
        check.result, check.driver = _schedule_result(reader, kl, fl, record, ci, cipher_str, nonce, keysize)
    return check


def safe_check_inode(reader: SafeReader, kl: dmcrypt.KernelLayout, fl: FscryptLayout,
                     record: MasterKey, ci: int) -> InodeCheck:
    """``check_inode`` that turns any failure on hostile/corrupt memory into an ``error:`` result."""
    try:
        return check_inode(reader, kl, fl, record, ci)
    except Exception as error:  # noqa: BLE001 - one bad inode must never kill the plugin
        vollog.debug("inode check at %#x failed", ci, exc_info=True)
        return InodeCheck(address=ci, result="error:%s" % type(error).__name__)


def _derive(record: MasterKey, nonce: bytes, keysize: int) -> Optional[bytes]:
    if record.spec_type == KEY_SPEC_DESCRIPTOR:
        return derive_v1_file_key(record.raw, nonce, keysize) if len(record.raw) >= keysize else None
    return derive_v2_file_key(record.hkdf, nonce, keysize) if record.hkdf else None


def _schedule_result(reader: SafeReader, kl: dmcrypt.KernelLayout, fl: FscryptLayout, record: MasterKey,
                     ci: int, cipher_str: str, nonce: bytes, keysize: int) -> Tuple[str, str]:
    derived = _derive(record, nonce, keysize)
    if derived is None:
        return "skipped:no-secret", ""
    expected = aes_keys_of(cipher_str, derived)
    if expected is None:
        return "skipped:cipher(%s)" % cipher_str, ""
    skcipher = reader.ptr(ci + fl["fscrypt_inode_info.ci_enc_key"] + fl["fscrypt_prepared_key.tfm"])
    tfm = dmcrypt.read_tfm(reader, kl, skcipher + kl["crypto_skcipher.base"]) if skcipher else None
    if tfm is None:
        return "no-schedule", ""
    schedules = dmcrypt.collect_schedules(reader, kl, tfm, reader.byteorder)
    return compare_schedules(expected, [s.key for s in schedules]), tfm.driver


# --------------------------------------------------------------------------- verdict


def identifier_context(record: MasterKey) -> int:
    """HKDF context of the key identifier: 8 for v6.16+ hardware-wrapped keys, else 1."""
    if record.hw_wrapped:
        return hk.HKDF_CONTEXT_KEY_IDENTIFIER_FOR_HW_WRAPPED_KEY
    return hk.HKDF_CONTEXT_KEY_IDENTIFIER_FOR_RAW_KEY


def identifier_from_state(state: HkdfState, context: int) -> bytes:
    info = hk.fscrypt_hkdf_info(context, b"")
    return hk.hkdf_expand_sha512_from_midstates(state.ipad, state.opad, info, hk.FSCRYPT_KEY_IDENTIFIER_SIZE)


def _identifier_oracle(record: MasterKey, notes: List[str]) -> Tuple[bool, Optional[str]]:
    """``(passed, contradiction)`` of the v2 identifier oracle; notes get the reasons it did not run."""
    if record.hkdf is None:
        notes.append(record.hkdf_why or "no HKDF state")
        return False, None
    context = identifier_context(record)
    if identifier_from_state(record.hkdf, context) == record.key_ref:
        return True, None
    why = "HKDF identifier (context %d) from the %s midstates != mk_spec identifier" % (
        context, record.hkdf.layout)
    if record.hw_wrapped:  # the inline-crypto secret path is unverified on real data: never reject
        notes.append(why + " (hardware-wrapped key)")
        return False, None
    return False, why


def _inode_notes(record: MasterKey, notes: List[str]) -> Tuple[int, int]:
    results = [check.result for check in record.inodes]
    matches, mismatches, partial = results.count("match"), results.count("mismatch"), results.count("partial")
    notes.append("inodes: %d listed, %d match, %d partial, %d mismatch, %d other" % (
        len(results), matches, partial, mismatches, len(results) - matches - mismatches - partial))
    if partial:
        notes.append("%d inode transform(s) hold only part of the derived key (e.g. one XTS half); "
                     "not counted as a match" % partial)
    return matches, mismatches


def decide(record: MasterKey, guessed: Sequence[str] = ()) -> Tuple[str, str]:
    """``(status, detail)`` for a key whose ``hkdf``/``inodes`` are filled.

    A contradiction gives ``rejected`` and a passed oracle ``oracle:<kinds>`` -- both only on
    ISF offsets; on guessed offsets either outcome is ``unverified``.
    """
    oracles: List[str] = []
    notes = [record.detail] if record.detail else []
    contradiction = None
    if record.spec_type == KEY_SPEC_IDENTIFIER:
        passed, contradiction = _identifier_oracle(record, notes)
        oracles += ["identifier"] if passed else []
    elif not record.raw or not any(record.raw):
        notes.append("mk_secret raw key is empty/zero (size %d)" % record.secret_size)
    elif keyring.fscrypt_v1_descriptor(record.raw) == record.key_ref.hex():
        oracles.append("descriptor")
    matches, mismatches = _inode_notes(record, notes)
    if mismatches and contradiction is None:
        contradiction = "%d inode transform(s) hold AES keys not derived from this secret" % mismatches
    if matches:
        oracles.append("per-file-schedule")
    if record.present is False:
        notes.append("mk_present = 0 (key removed, inodes still busy)")
    if contradiction is not None:
        if guessed:
            return UNVERIFIED, "; ".join(notes + ["contradicts on guessed offsets (%s): %s" % (
                ", ".join(guessed), contradiction)])
        return REJECTED, "; ".join(notes + [contradiction])
    if not oracles:
        return UNVERIFIED, "; ".join(notes + ["no oracle fired"])
    label = PROVEN_PREFIX + "+".join(oracles)
    if guessed:
        return UNVERIFIED, "; ".join(notes + ["%s passed, but on guessed offsets (%s)" % (
            label, ", ".join(guessed))])
    return label, "; ".join(notes)


def midstates_hex(state: Tuple[int, ...]) -> str:
    """A SHA-512 chaining state as the 64-byte big-endian digest-order hex string."""
    return struct.pack(">8Q", *state).hex()


# --------------------------------------------------------------------------- plugin


class Fscrypt(interfaces.plugins.PluginInterface):
    """Lists fscrypt master keys of every superblock keyring and proves them from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.ChoiceRequirement(
                name="export", choices=["json"], optional=True,
                description="Write fscrypt.json (v1 raw keys, v2 HKDF-PRK midstates, per-inode checks)"),
            requirements.BooleanRequirement(
                name="verbose", optional=True, default=False,
                description="Add a Detail column and one child row per decrypted inode"),
        ]

    def _setup(self) -> None:
        self.vmlinux, self.layer, self.reader = kernel_reader(self.context, self.config["kernel"])
        self.fl = FscryptLayout.from_module(self.vmlinux)
        self.kl = dmcrypt.KernelLayout.from_module(self.vmlinux)
        self.guessed = sorted(set(self.fl.guessed()) | {
            k for k in self.kl.defaulted() if k.startswith("crypto_")})
        if self.guessed:
            vollog.warning("ISF lacks %d fscrypt/crypto offsets, guessed from the x86_64 6.8 layout "
                           "(no key will be labelled proven): %s", len(self.guessed), ", ".join(self.guessed))

    def _super_blocks(self) -> Optional[int]:
        # canonical, comparable with the list pointers read from memory (iter_list also accepts both)
        return symbol_address(self.vmlinux, "super_blocks", self.layer)

    def _collect(self) -> List[MasterKey]:
        head = self._super_blocks()
        if self.fl.supported == "no-fs-encryption" or head is None:
            vollog.warning("no fscrypt support in this kernel's ISF (super_block.s_master_keys or "
                           "super_blocks missing): nothing to walk")
            return []
        records: List[MasterKey] = []
        for sb in iter_superblocks(self.reader, self.fl, head):
            master_keys = self.reader.ptr(sb + self.fl["super_block.s_master_keys"])
            if master_keys:
                records.extend(self._keys_of(sb, master_keys))
        return records

    def _keys_of(self, sb: int, master_keys: int) -> List[MasterKey]:
        device, fs_type = superblock_names(self.reader, self.fl, sb)
        if self.fl.supported:
            return [MasterKey(address=master_keys, superblock=sb, device=device, fs_type=fs_type, bucket=-1,
                              status="error:" + self.fl.supported,
                              detail="s_master_keys is a struct key keyring (< v6.1): not decoded")]
        records = []
        for bucket, mk in iter_master_keys(self.reader, self.fl, master_keys):
            record = read_master_key(self.reader, self.fl, mk, sb, device, fs_type, bucket)
            if record is None:
                vollog.info("%s: bucket %d entry %#x is not a plausible fscrypt_master_key", device, bucket, mk)
                continue
            self._prove(record)
            records.append(record)
        return records

    def _prove(self, record: MasterKey) -> None:
        if record.spec_type == KEY_SPEC_IDENTIFIER:
            record.hkdf, record.hkdf_why = read_hkdf_state(self.reader, self.kl, self.fl, record.address)
        record.inodes = [safe_check_inode(self.reader, self.kl, self.fl, record, ci)
                         for ci in iter_decrypted_inodes(self.reader, self.fl, record.address)]
        record.status, record.detail = decide(record, self.guessed)

    # ------------------------------------------------------------------ output

    def _modes(self, record: MasterKey) -> str:
        policies = [c.policy for c in record.inodes if c.policy and not c.result.startswith("invalid")]
        return policy_text(policies[0]) if policies else "?"

    def _row(self, record: MasterKey) -> Tuple:
        na = renderers.NotApplicableValue()
        checked = [c for c in record.inodes if c.result in ("match", "partial", "mismatch")]
        if record.spec_type == KEY_SPEC_DESCRIPTOR:
            key_hex, secret = (record.raw.hex() or na), "raw"
        elif record.hkdf is not None:
            key_hex, secret = na, "wiped; HKDF-PRK midstates (%s) in --export json" % record.hkdf.layout
        else:
            key_hex, secret = na, "none"
        row = [format_hints.Hex(record.superblock), record.device, record.fs_type, record.version,
               record.key_ref.hex() or na, self._modes(record), record.secret_size or na, key_hex, secret,
               "%d/%d" % (sum(1 for c in checked if c.result == "match"), len(checked)),
               record.status, self.fl.provenance(self.guessed), format_hints.Hex(record.address)]
        if self.config.get("verbose"):
            row.append(record.detail)
        return tuple(row)

    def _inode_row(self, check: InodeCheck) -> Tuple:
        na = renderers.NotApplicableValue()
        return (na, "inode %s" % (check.ino if check.ino is not None else "?"), na, na, na,
                "%s (%s)" % (check.mode, policy_text(check.policy)), na, na, na, na, check.result, na,
                format_hints.Hex(check.address), check.driver or "")

    def _columns(self) -> List[Tuple[str, Any]]:
        columns = [("Superblock", format_hints.Hex), ("Device", str), ("FsType", str), ("Policy", str),
                   ("KeyRef", str), ("Modes", str), ("KeySize", int), ("KeyHex", str), ("Secret", str),
                   ("Inodes", str), ("Proven", str), ("Offsets", str), ("Offset(V)", format_hints.Hex)]
        if self.config.get("verbose"):
            columns.append(("Detail", str))
        return columns

    def _generator(self, records: List[MasterKey]) -> Iterator[Tuple[int, Tuple]]:
        for record in records:
            yield 0, self._row(record)
            if self.config.get("verbose"):
                for check in record.inodes:
                    yield 1, self._inode_row(check)

    def _json_report(self, records: List[MasterKey]) -> List[Dict[str, Any]]:
        report = []
        for record in records:
            entry: Dict[str, Any] = {
                "superblock": record.superblock, "device": record.device, "fs_type": record.fs_type,
                "policy_version": record.version, "key_ref_hex": record.key_ref.hex(),
                "modes": self._modes(record), "secret_size": record.secret_size,
                "master_key_hex": record.raw.hex() if record.spec_type == KEY_SPEC_DESCRIPTOR else None,
                "hkdf_prk_midstates": None, "status": record.status, "detail": record.detail,
                "offsets": self.fl.provenance(self.guessed), "fscrypt_master_key": record.address,
                "inodes": [{"fscrypt_inode_info": c.address, "ino": c.ino, "mode": c.mode,
                            "policy": policy_text(c.policy), "result": c.result, "driver": c.driver}
                           for c in record.inodes],
            }
            if record.hkdf is not None:
                entry["hkdf_prk_midstates"] = {
                    "layout": record.hkdf.layout, "driver": record.hkdf.driver,
                    "ipad_sha512_state_hex": midstates_hex(record.hkdf.ipad),
                    "opad_sha512_state_hex": midstates_hex(record.hkdf.opad),
                    "note": "master key wiped by the kernel; these SHA-512 chaining states of "
                            "HMAC(PRK) derive every fscrypt subkey (HKDF-Expand)"}
            report.append(entry)
        return report

    def run(self) -> renderers.TreeGrid:
        self._setup()
        records = self._collect()
        vollog.info("linux.fscrypt: %d master keys, %d proven", len(records),
                    sum(1 for r in records if r.proven))
        if self.config.get("export") == "json":
            with self.open("fscrypt.json") as handle:
                handle.write(json.dumps(self._json_report(records), indent=1).encode("utf-8"))
        return renderers.TreeGrid(self._columns(), self._generator(records))
