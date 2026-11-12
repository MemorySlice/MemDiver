"""``linux.ecryptfs`` -- eCryptfs per-file encryption keys (FEKs), proven by kernel self-consistency.

Walk
----
``super_blocks`` -> every ``super_block`` whose ``s_type`` is ``ecryptfs_fs_type`` (or whose
``s_type->name`` is ``"ecryptfs"`` when eCryptfs is a module) -> ``s_inodes`` (``inode.i_sb_list``)
-> ``container_of(inode, struct ecryptfs_inode_info, vfs_inode)`` (``ecryptfs_inode_to_private``,
fs/ecryptfs/ecryptfs_kernel.h) -> the embedded ``struct ecryptfs_crypt_stat``:
``key[ECRYPTFS_MAX_KEY_BYTES]`` is the FEK, ``key[:key_size]`` the used part.  The upper path comes
from the inode's dentry alias and the mount (``super_block.s_mounts``); the lower inode from
``ecryptfs_inode_info.wii_inode``; the lower path from the dentry's ``ecryptfs_dentry_info.lower_path``.
The mount's auth tokens (``ecryptfs_sb_info.mount_crypt_stat.global_auth_tok_list``) give the
FEKEK signature(s) -- the description ``linux.keyring`` prints for the ``user`` key holding the
``ecryptfs_auth_tok`` -- and the key itself is decoded with ``keyring.decode_ecryptfs`` (FEKEK proven
there by ``signature == SHA-512(FEKEK)[:8]``).  Mount paths are resolved once per mount; every list
and path walk is cycle-safe and bounded, and a run of unreadable ``crypt_stat``s stops that mount
with one summary ``error:`` row.

Offsets
-------
Every offset and struct size comes from the vmlinux ISF (eCryptfs is built in on Ubuntu/Debian
kernels); when the ISF lacks the eCryptfs types (built as a module) they are taken from the
``ecryptfs`` module's own BTF in the image (``btf-memory``, trusted recoveries only).  Otherwise an
LP64 6.8 layout is guessed and announced.  **Any** guessed offset or size -- on the key path *or* on
the walk that attributes the key to a mount/inode/file -- demotes every row to ``unverified``, and the
``Offsets`` column lists what was guessed.  The auth token's ``keyring proven`` status is likewise
demoted when ``linux.keyring``'s key/auth-token offsets were guessed.

Proof (``Proven`` is ``oracle:<kind>`` | ``unverified`` | ``rejected`` | ``error:<why>``)
------------------------------------------------------------------------------------------
* **root IV** (``oracle:ecryptfs-root-iv``): ``ecryptfs_compute_root_iv()`` (fs/ecryptfs/crypto.c,
  v6.8) runs only with ``ECRYPTFS_KEY_VALID`` set and stores
  ``root_iv[:iv_bytes] = MD5(key[:key_size])[:iv_bytes]`` (``crypto_shash_tfm_digest`` on the
  ``md5`` ``hash_tfm``); on failure it zeroes ``root_iv`` and sets ``ECRYPTFS_SECURITY_WARNING``.
  The kernel only ever sets ``iv_bytes = ECRYPTFS_DEFAULT_IV_BYTES`` (16), so the oracle applies
  only then (a 1-byte IV would pass a wrong key 1 time in 256).  A non-zero ``root_iv`` equal to the
  recomputed MD5 proves the key bytes; a mismatch rejects (on trusted offsets).
* **tfm schedule** (``...+tfm-schedule``): once ``ECRYPTFS_KEY_SET`` is set, ``crypt_scatterlist()``
  has keyed ``crypt_stat->tfm`` (``cbc(<cipher>)``) with ``key[:key_size]``, so its AES key schedule
  (``linux.dmcrypt``'s schedule search, O1 of ``struct crypto_aes_ctx``) must expand that key.  It
  proves alone only when the root IV is not applicable; a schedule of another key demotes.  It is
  only consulted when the ``crypto_*`` offsets come from the ISF.
* **tag 3** (``...+ecryptfs-tag3``): page 0 of the lower inode (read from the page cache through
  ``i_mapping``, only pages whose ``page->mapping`` is that ``address_space``) holds the file's
  header (fs/ecryptfs/crypto.c ``ecryptfs_write_headers_virt``): size(8), marker
  ``m1, m1 ^ 0x3c81b7f5`` (8), flags(4), header extent size(4), extents at front(2), then the
  key packet set at offset 26 (fs/ecryptfs/keystore.c).  A passphrase mount writes a tag-3
  packet (version 4, cipher code 7/8/9 = AES-128/192/256, S2K 3, MD5, salt[8], coded count,
  the FEK wrapped by AES-ECB under ``FEKEK[:key_bytes]``) followed by a tag-11 packet carrying
  the FEKEK signature.  The FEKEK of a mount auth token unwrapping that packet to
  ``key[:key_size]`` proves the FEK (a wrong key passes 1 time in 2^128) AND pairs the file with
  the FEKEK.  A tag-3 mismatch never rejects: with a passing root IV the FEK stays proven and the
  FEKEK-to-mount pairing is flagged; without the root IV it leaves the FEK ``unverified``.  A lower
  page 0 that is not resident, a tag-1 (public-key) set or no FEKEK makes the check ``n/a``.
* A zero key, ``key_size`` 0 or above 64, or ``ECRYPTFS_KEY_VALID`` unset is never proven.

Exports (``--export``)
----------------------
``json`` (ecryptfs.json, every file), ``fek`` (ecryptfs_fek.csv: ``lower_path,inode,cipher,fek_hex``
for proven FEKs only, ``inode`` = the lower inode number) and ``fekek`` (ecryptfs_fekek.txt:
``<sig> <fekek_hex>`` per mount auth token whose FEKEK is keyring-proven).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import btf_layouts, keyring
from .dmcrypt import KernelLayout, collect_schedules, read_tfm
from .kernel_common import (DEFAULT, ISF, IsfLayout, SafeReader, arch_of, isf_offset, isf_size, iter_list,
                            kernel_reader, symbol_address, write_text)
from .secrets import aes, pagecache

vollog = logging.getLogger(__name__)

ECRYPTFS_MAX_KEY_BYTES = 64  # include/uapi/linux/ecryptfs.h
ECRYPTFS_MAX_IV_BYTES = 16  # fs/ecryptfs/ecryptfs_kernel.h
ECRYPTFS_DEFAULT_IV_BYTES = 16  # the only value ecryptfs_set_default_sizes() ever sets
ECRYPTFS_SIG_SIZE_HEX = 16
# fs/ecryptfs/ecryptfs_kernel.h (v6.8) crypt_stat->flags
ECRYPTFS_ENCRYPTED = 0x00000004
ECRYPTFS_SECURITY_WARNING = 0x00000008
ECRYPTFS_KEY_VALID = 0x00000040
ECRYPTFS_KEY_SET = 0x00000200
ECRYPTFS_AUTH_TOK_INVALID = 0x00000001  # ecryptfs_global_auth_tok.flags
ECRYPTFS_AUTH_TOK_FNEK = 0x00000002
FS_TYPE_NAME = "ecryptfs"

MAX_SUPERBLOCKS = 4096
MAX_INODES = 1 << 20
MAX_AUTH_TOKS = 64  # per mount
MAX_KEYSIGS = 16  # per crypt_stat (the kernel adds one per mount auth token)
MAX_UNREADABLE_RUN = 64  # consecutive unreadable crypt_stats before a mount's walk is abandoned
MAX_PATH_PARTS = 256
MAX_MOUNT_HOPS = 64
NAME_LIMIT = 256

ROOT_IV, TFM_SCHEDULE = "ecryptfs-root-iv", "tfm-schedule"
UNVERIFIED, REJECTED = "unverified", "rejected"
ERROR_UNREADABLE, ERROR_UNREADABLE_RUN = "error:unreadable-crypt_stat", "error:unreadable-run"
# linux.keyring offsets the auth-token decode reads (a guessed one demotes "keyring proven").
AUTH_TOK_KEY_PREFIXES = ("key.", "key_type.", "user_key_payload.", "ecryptfs_auth_tok.", "ecryptfs_password.")


# --------------------------------------------------------------------------- layout

# "type.member[.member]" -> LP64 6.8 (x86_64 6.8.0-136-generic ISF) fallback offset.
_FIELDS = {
    "list_head.next": 0, "hlist_head.first": 0, "hlist_node.next": 0,
    "super_block.s_list": 0, "super_block.s_type": 40, "super_block.s_fs_info": 912,
    "super_block.s_inodes": 1352, "super_block.s_id": 960, "super_block.s_mounts": 224,
    "file_system_type.name": 0,
    "inode.i_sb_list": 280, "inode.i_ino": 80, "inode.i_sb": 56, "inode.i_mode": 0,
    "inode.i_size": 96, "inode.i_dentry": 312,
    "dentry.d_parent": 24, "dentry.d_name": 32, "dentry.d_fsdata": 128, "dentry.d_u.d_alias": 176,
    "qstr.name": 8,
    "mount.mnt_instance": 128, "mount.mnt_mountpoint": 24, "mount.mnt_parent": 16,
    "mount.mnt": 32, "mount.mnt_devname": 144, "vfsmount.mnt_root": 0,
    "path.mnt": 0, "path.dentry": 8,
    "ecryptfs_inode_info.vfs_inode": 0, "ecryptfs_inode_info.wii_inode": 632,
    "ecryptfs_inode_info.crypt_stat": 688,
    "ecryptfs_crypt_stat.flags": 0, "ecryptfs_crypt_stat.iv_bytes": 8,
    "ecryptfs_crypt_stat.key_size": 32, "ecryptfs_crypt_stat.mount_crypt_stat": 56,
    "ecryptfs_crypt_stat.tfm": 64, "ecryptfs_crypt_stat.cipher": 80, "ecryptfs_crypt_stat.key": 112,
    "ecryptfs_crypt_stat.root_iv": 176, "ecryptfs_crypt_stat.keysig_list": 192,
    "ecryptfs_sb_info.wsi_sb": 0, "ecryptfs_sb_info.mount_crypt_stat": 8,
    "ecryptfs_mount_crypt_stat.flags": 0, "ecryptfs_mount_crypt_stat.global_auth_tok_list": 8,
    "ecryptfs_global_auth_tok.flags": 0, "ecryptfs_global_auth_tok.mount_crypt_stat_list": 8,
    "ecryptfs_global_auth_tok.global_auth_tok_key": 24, "ecryptfs_global_auth_tok.sig": 32,
    "ecryptfs_key_sig.crypt_stat_list": 0, "ecryptfs_key_sig.keysig": 16,
    "ecryptfs_dentry_info.lower_path": 0,
}
_SIZES = {"ecryptfs_crypt_stat": 304, "ecryptfs_crypt_stat.cipher": 32, "super_block.s_id": 32}
ECRYPTFS_TYPES = ("ecryptfs_inode_info", "ecryptfs_crypt_stat", "ecryptfs_sb_info",
                  "ecryptfs_mount_crypt_stat", "ecryptfs_global_auth_tok", "ecryptfs_key_sig",
                  "ecryptfs_dentry_info")
# The offsets the key bytes are read through (reported separately in the warning).
KEY_PATH_KEYS = frozenset(k for k in _FIELDS if k.startswith(("ecryptfs_inode_info.", "ecryptfs_crypt_stat.")))


@dataclass
class EcryptfsLayout(IsfLayout):
    """Offsets (``"type.member" -> offset``) and sizes with their source (isf | btf-memory | default).

    A bare ``EcryptfsLayout()`` (unit tests) has no sources and counts as fully known.
    """

    offsets: Dict[str, int] = field(default_factory=lambda: dict(_FIELDS))
    sizes: Dict[str, int] = field(default_factory=lambda: dict(_SIZES))
    size_sources: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_module(cls, module: Any, btf_structs: Optional[Dict[str, Any]] = None,
                    btf_source: str = "btf-memory") -> "EcryptfsLayout":
        layout, btf_structs = cls(), btf_structs or {}

        def from_btf(key: str) -> Optional[Tuple[int, str]]:
            type_name, *path = key.split(".")
            offset = _btf_offset(btf_structs, type_name, path)
            return None if offset is None else (offset, btf_source)

        layout.resolve(lambda key: isf_offset(module, *key.split(".", 1)), from_btf)
        layout._sizes_from(module, btf_structs, btf_source)
        return layout

    def _sizes_from(self, module: Any, btf_structs: Dict[str, Any], btf_source: str) -> None:
        for key in list(self.sizes):
            type_name, _dot, member = key.partition(".")
            size = isf_size(module, key)
            if size is not None:
                self.sizes[key], self.size_sources[key] = size, ISF
                continue
            size = _btf_size(btf_structs.get(type_name), member)
            if size:
                self.sizes[key], self.size_sources[key] = size, btf_source
            else:
                self.size_sources[key] = DEFAULT

    def guessed(self) -> List[str]:
        """Every offset/size that is only the LP64 6.8 guess (sizes as ``sizeof(...)``)."""
        sizes = ["sizeof(%s)" % k for k, v in self.size_sources.items() if v == DEFAULT]
        return self.defaulted() + sorted(sizes)

    def key_path_guessed(self) -> List[str]:
        return [k for k in self.guessed()
                if k in KEY_PATH_KEYS or k.startswith("sizeof(ecryptfs_crypt_stat")]

    def source(self) -> str:
        """Provenance of the trusted offsets (``isf``, ``btf-memory``, ``isf+btf-memory``)."""
        found = {v for v in list(self.sources.values()) + list(self.size_sources.values()) if v != DEFAULT}
        return "+".join(sorted(found)) if found else (DEFAULT if self.sources else ISF)


def _btf_offset(structs: Dict[str, Any], type_name: str, path: List[str]) -> Optional[int]:
    """Single-level member offset from ``btf_memory.BtfStruct`` layouts (eCryptfs structs only)."""
    struct = structs.get(type_name)
    if struct is None or len(path) != 1:
        return None
    found = struct.member(path[0])
    return found.offset if found is not None and not found.bitfield_size else None


def _btf_size(struct: Optional[Any], member: str) -> Optional[int]:
    if struct is None:
        return None
    if not member:
        return struct.size
    found = struct.member(member)
    return found.size if found is not None else None


# The lower file's page cache (``inode.i_mapping`` + ``pagecache``'s xarray/page offsets).
_PAGECACHE_FIELDS = dict(pagecache.PAGECACHE_DEFAULTS, **{"inode.i_mapping": 64})


@dataclass
class PagecacheLayout(IsfLayout):
    """Offsets the lower-header read goes through (a guess here never rejects: see ``tag3``)."""

    offsets: Dict[str, int] = field(default_factory=lambda: dict(_PAGECACHE_FIELDS))

    @classmethod
    def from_module(cls, module: Any) -> "PagecacheLayout":
        layout = cls()
        layout.resolve(lambda key: _isf_value(module, key))
        return layout


def _isf_value(module: Any, key: str) -> Optional[int]:
    """``"type.member"`` -> ISF offset, ``"sizeof(type)"`` -> ISF size."""
    if key.startswith("sizeof(") and key.endswith(")"):
        return isf_size(module, key[len("sizeof("):-1])
    return isf_offset(module, *key.split(".", 1))


# --------------------------------------------------------------------------- crypt_stat + oracles


@dataclass
class CryptStat:
    address: int
    flags: int
    iv_bytes: int
    key_size: int
    mount_crypt_stat: int
    tfm: int
    cipher: str
    key_area: bytes  # all ECRYPTFS_MAX_KEY_BYTES of key[]
    root_iv: bytes

    @property
    def key(self) -> bytes:
        return self.key_area[:self.key_size] if 0 < self.key_size <= ECRYPTFS_MAX_KEY_BYTES else b""

    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)

    def looks_used(self) -> bool:
        """A crypt_stat the kernel put a key into (directories and fresh inodes have none)."""
        return self.has(ECRYPTFS_KEY_VALID) or self.has(ECRYPTFS_ENCRYPTED) or self.key_size > 0


def parse_crypt_stat(data: Optional[bytes], address: int, el: EcryptfsLayout,
                     byteorder: str = "little", pointer_size: int = 8) -> Optional[CryptStat]:
    """Decode the bytes of one ``struct ecryptfs_crypt_stat`` (None when unreadable)."""
    if not data or len(data) < el.sizes["ecryptfs_crypt_stat"]:
        return None

    def num(member: str, size: int) -> int:
        offset = el["ecryptfs_crypt_stat." + member]
        return int.from_bytes(data[offset:offset + size], byteorder)

    cipher_at = el["ecryptfs_crypt_stat.cipher"]
    cipher_raw = data[cipher_at:cipher_at + el.sizes["ecryptfs_crypt_stat.cipher"]].split(b"\0", 1)[0]
    key_at, iv_at = el["ecryptfs_crypt_stat.key"], el["ecryptfs_crypt_stat.root_iv"]
    return CryptStat(
        address=address, flags=num("flags", 4), iv_bytes=num("iv_bytes", pointer_size),
        key_size=num("key_size", pointer_size), mount_crypt_stat=num("mount_crypt_stat", pointer_size),
        tfm=num("tfm", pointer_size), cipher=cipher_raw.decode("ascii", "replace"),
        key_area=data[key_at:key_at + ECRYPTFS_MAX_KEY_BYTES],
        root_iv=data[iv_at:iv_at + ECRYPTFS_MAX_IV_BYTES])


def _md5(data: bytes) -> bytes:
    try:
        return hashlib.md5(data, usedforsecurity=False).digest()  # type: ignore[call-arg]
    except TypeError:  # Python < 3.9
        return hashlib.md5(data).digest()  # nosec B324 - recomputing the kernel's own MD5 IV


def key_unusable(cs: CryptStat) -> str:
    """Why this crypt_stat can never prove a key ('' when it can)."""
    if not 0 < cs.key_size <= ECRYPTFS_MAX_KEY_BYTES:
        return "key_size %d" % cs.key_size
    if not any(cs.key):
        return "zero key"
    if not cs.has(ECRYPTFS_KEY_VALID):
        return "ECRYPTFS_KEY_VALID not set"
    return ""


def root_iv_check(cs: CryptStat) -> Tuple[str, str]:
    """``(pass|fail|n/a, detail)`` of ``root_iv == MD5(key[:key_size])`` (16-byte IVs only)."""
    why = key_unusable(cs)
    if why:
        return "n/a", why
    if cs.iv_bytes != ECRYPTFS_DEFAULT_IV_BYTES:
        return "n/a", "root IV n/a: iv_bytes %d != %d (ECRYPTFS_DEFAULT_IV_BYTES)" % (
            cs.iv_bytes, ECRYPTFS_DEFAULT_IV_BYTES)
    if not any(cs.root_iv):
        return "n/a", "root_iv zeroed (ecryptfs_compute_root_iv failed or not run)"
    if _md5(cs.key) == cs.root_iv[:ECRYPTFS_DEFAULT_IV_BYTES]:
        return "pass", "MD5(key) == root_iv"
    return "fail", "MD5(key) != root_iv"


def schedule_check(schedule_keys: Optional[Sequence[bytes]], cs: CryptStat) -> Tuple[str, str]:
    """``(pass|fail|n/a, detail)``: does ``crypt_stat->tfm`` hold the schedule of ``key[:key_size]``?"""
    if not cs.has(ECRYPTFS_KEY_SET) or not cs.tfm:
        return "n/a", "tfm not keyed (ECRYPTFS_KEY_SET unset)"
    if schedule_keys is None:
        return "n/a", "tfm schedule not checked"
    if not schedule_keys:
        return "n/a", "no AES schedule found in the tfm"
    if any(k == cs.key for k in schedule_keys):
        return "pass", "tfm AES schedule expands key"
    return "fail", "tfm AES schedule(s) of another key"


# --------------------------------------------------------------------------- lower-file header (tag 3)

MAGIC_ECRYPTFS_MARKER = 0x3C81B7F5  # fs/ecryptfs/ecryptfs_kernel.h
PACKET_SET_OFFSET = 26  # size(8) + marker(8) + flags(4) + header extent size(4) + extents at front(2)
TAG1_PACKET, TAG3_PACKET, TAG11_PACKET = 0x01, 0x8C, 0xED  # ECRYPTFS_TAG_{1,3,11}_PACKET_TYPE
TAG3_VERSION, S2K_SALTED_ITERATED = 0x04, 0x03
ECRYPTFS_SALT_SIZE, ECRYPTFS_SIG_SIZE = 8, 8
TAG11_BINARY_FORMAT = 0x62
AES_CIPHER_CODES = {0x07: 16, 0x08: 24, 0x09: 32}  # RFC2440_CIPHER_AES_128/192/256
MAX_PACKETS = 32
TAG3 = "ecryptfs-tag3"
PAGE_SIZE = 4096
NOT_RESIDENT = "lower page 0 not resident in the page cache"


@dataclass
class Tag3:
    """One tag-3 packet (keystore.c ``parse_tag_3_packet``); ``count`` = decoded hash iterations."""

    cipher_code: int
    key_bytes: Optional[int]  # AES key size of the cipher code, None for a non-AES cipher
    salt: bytes
    count: int
    wrapped: bytes  # the encrypted FEK (AES-192 FEKs are padded to 32 bytes)
    sig: Optional[str] = None  # FEKEK signature of the tag-11 packet that follows, hex


def has_header_marker(header: bytes) -> bool:
    """``m2 == m1 ^ MAGIC_ECRYPTFS_MARKER`` at offset 8 (crypto.c ``ecryptfs_validate_marker``)."""
    if len(header) <= PACKET_SET_OFFSET:
        return False
    m1, m2 = int.from_bytes(header[8:12], "big"), int.from_bytes(header[12:16], "big")
    return m1 ^ m2 == MAGIC_ECRYPTFS_MARKER


def packet_length(data: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """``(body size, length bytes)`` (keystore.c ``ecryptfs_parse_packet_length``), else None."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first < 192:
        return first, 1
    if first < 224 and pos + 1 < len(data):
        return (first - 192) * 256 + data[pos + 1] + 192, 2
    return None  # five-byte lengths are unsupported by the kernel too


def iter_packets(header: bytes) -> Iterator[Tuple[int, bytes]]:
    """``(tag, body)`` of every packet of the key packet set, up to the 0x00 terminator."""
    pos = PACKET_SET_OFFSET
    for _ in range(MAX_PACKETS):
        if pos >= len(header) or header[pos] == 0:
            return
        length = packet_length(header, pos + 1)
        if length is None or pos + 1 + length[1] + length[0] > len(header):
            return
        start = pos + 1 + length[1]
        yield header[pos], header[start:start + length[0]]
        pos = start + length[0]


def _tag3_body(body: bytes) -> Optional[Tag3]:
    """version 4, cipher code, S2K 3, hash id, salt[8], coded count, encrypted key."""
    head = 4 + ECRYPTFS_SALT_SIZE + 1
    if len(body) <= head or body[0] != TAG3_VERSION or body[2] != S2K_SALTED_ITERATED:
        return None
    coded = body[head - 1]
    count = (16 + (coded & 15)) << ((coded >> 4) + 6)  # RFC 2440 3.6.1.3
    return Tag3(body[1], AES_CIPHER_CODES.get(body[1]), body[4:head - 1], count, body[head:])


def _tag11_sig(body: bytes) -> Optional[str]:
    """The FEKEK signature in a tag-11 literal packet (format 0x62, "_CONSOLE", date[4], sig[8])."""
    if len(body) < 2 or body[0] != TAG11_BINARY_FORMAT:
        return None
    contents = body[2 + body[1] + 4:]
    return contents.hex() if len(contents) == ECRYPTFS_SIG_SIZE else None


def parse_tag3s(header: bytes) -> List[Tag3]:
    """Every tag-3 packet of an eCryptfs lower-file header (empty without the marker)."""
    if not has_header_marker(header):
        return []
    packets, found = list(iter_packets(header)), []
    for index, (tag, body) in enumerate(packets):
        tag3 = _tag3_body(body) if tag == TAG3_PACKET else None
        if tag3 is None:
            continue
        if index + 1 < len(packets) and packets[index + 1][0] == TAG11_PACKET:
            tag3.sig = _tag11_sig(packets[index + 1][1])
        found.append(tag3)
    return found


def parse_tag3(header: bytes) -> Optional[Tag3]:
    """The first tag-3 packet of an eCryptfs lower-file header, else None."""
    found = parse_tag3s(header)
    return found[0] if found else None


def _no_tag3_reason(header: bytes) -> str:
    if not has_header_marker(header):
        return "no eCryptfs header marker in lower page 0 (metadata in xattr?)"
    if any(tag == TAG1_PACKET for tag, _body in iter_packets(header)):
        return "tag-1 (public-key) packet: tag-3 n/a"
    return "no tag-3 packet in the lower header"


def tag3_unwraps(tag3: Tag3, fekek: bytes, fek: bytes) -> Optional[bool]:
    """Does AES-ECB(``fekek[:key_bytes]``)^-1 of the wrapped key give ``fek``?  None = not checkable."""
    size = tag3.key_bytes
    if size is None or len(fekek) < size or len(tag3.wrapped) < size or len(tag3.wrapped) % 16:
        return None
    if len(fek) != size:
        return False  # the header's cipher code names another key size than crypt_stat
    return aes.ecb_decrypt(fekek[:size], tag3.wrapped)[:size] == fek


def tag3_check(header: bytes, fekek: bytes, fek: bytes) -> Tuple[str, str]:
    """``(pass|fail|n/a, detail)``: does ``fekek`` unwrap a tag-3 packet of ``header`` to ``fek``?"""
    tags = parse_tag3s(header)
    if not tags:
        return "n/a", _no_tag3_reason(header)
    if not fek or not fekek:
        return "n/a", "tag-3 n/a: no FEK or FEKEK"
    results = [(tag, tag3_unwraps(tag, fekek, fek)) for tag in tags]
    for tag, ok in results:
        if ok:
            return "pass", "tag-3%s unwraps to the FEK" % (" (sig %s)" % tag.sig if tag.sig else "")
    if any(ok is False for _tag, ok in results):
        return "fail", "tag-3 unwrapped with the FEKEK != FEK"
    return "n/a", "tag-3 not checkable (cipher code %#x, %d wrapped bytes)" % (
        tags[0].cipher_code, len(tags[0].wrapped))


@dataclass
class FekVerdict:
    proven: str  # oracle:<kind> | unverified | rejected | error:<why>
    detail: str
    root_iv: str = "n/a"
    schedule: str = "n/a"
    tag3: str = "n/a"


def _proof_label(iv: str, sched: str, tag3: str) -> str:
    """``ecryptfs-root-iv[+tfm-schedule]``, ``ecryptfs-tfm-schedule``, each ``[+ecryptfs-tag3]``."""
    parts: List[str] = []
    if iv == "pass":
        parts = [ROOT_IV] + ([TFM_SCHEDULE] if sched == "pass" else [])
    elif sched == "pass":
        parts = ["ecryptfs-" + TFM_SCHEDULE]
    if tag3 == "pass":
        parts.append(TAG3)
    return "+".join(parts)


def decide(cs: Optional[CryptStat], schedule: Tuple[str, str] = ("n/a", ""),
           guessed: Sequence[str] = (), tag3: Tuple[str, str] = ("n/a", "")) -> FekVerdict:
    """The single place a FEK becomes proven.  ``guessed`` = offsets/sizes that are only guesses."""
    if cs is None:
        return FekVerdict(ERROR_UNREADABLE, "crypt_stat could not be read")
    iv, iv_detail = root_iv_check(cs)
    sched, sched_detail = schedule if not key_unusable(cs) else ("n/a", "")
    tag, tag_detail = tag3 if not key_unusable(cs) else ("n/a", "")
    detail = "; ".join(d for d in (iv_detail, sched_detail, tag_detail) if d)
    if guessed:
        contradiction = "; contradicts on guessed offsets" if "fail" in (iv, sched, tag) else ""
        return FekVerdict(UNVERIFIED, detail + contradiction + "; guessed offsets: " + ", ".join(guessed),
                          iv, sched, tag)
    if iv == "fail":
        return FekVerdict(REJECTED, detail, iv, sched, tag)
    if sched == "fail":
        return FekVerdict(UNVERIFIED, detail + " (contradicts)", iv, sched, tag)
    if tag == "fail" and iv != "pass":
        return FekVerdict(UNVERIFIED, detail + " (tag-3 contradicts)", iv, sched, tag)
    label = _proof_label(iv, sched, tag)
    if not label:
        return FekVerdict(UNVERIFIED, detail, iv, sched, tag)
    pairing = " (FEKEK-to-mount pairing NOT confirmed: tag-3 fails)" if tag == "fail" else ""
    return FekVerdict("oracle:" + label, detail + pairing, iv, sched, tag)


# --------------------------------------------------------------------------- walk helpers


def container_of(address: int, member_offset_: int) -> int:
    return address - member_offset_


def crypt_stat_address(el: EcryptfsLayout, inode: int) -> int:
    """``&ecryptfs_inode_to_private(inode)->crypt_stat``."""
    return container_of(inode, el["ecryptfs_inode_info.vfs_inode"]) + el["ecryptfs_inode_info.crypt_stat"]


def dentry_name(reader: SafeReader, el: EcryptfsLayout, dentry: int) -> Optional[str]:
    name = reader.ptr(dentry + el["dentry.d_name"] + el["qstr.name"])
    return reader.cstring(name, NAME_LIMIT) if name else None


def dentry_parts(reader: SafeReader, el: EcryptfsLayout, dentry: Optional[int],
                 stop: Optional[int]) -> Optional[List[str]]:
    """Names from ``dentry`` up to (excluding) ``stop`` or the fs root, leaf first; None on a
    cycle, an unreadable dentry or more than ``MAX_PATH_PARTS`` levels."""
    parts: List[str] = []
    seen = set()
    while dentry and dentry != stop:
        if dentry in seen or len(parts) >= MAX_PATH_PARTS:
            return None
        seen.add(dentry)
        parent = reader.ptr(dentry + el["dentry.d_parent"])
        name = dentry_name(reader, el, dentry)
        if not parent or name is None:
            return None
        if parent == dentry:
            break
        parts.append(name)
        dentry = parent
    return parts


def join_path(base: str, parts: Sequence[str]) -> str:
    if not parts:
        return base
    return base.rstrip("/") + "/" + "/".join(reversed(parts))


def mount_path(reader: SafeReader, el: EcryptfsLayout, dentry: Optional[int], mount: int) -> Optional[str]:
    """Absolute path of ``dentry`` seen through ``struct mount`` ``mount`` (cycle-safe, bounded)."""
    parts: List[str] = []
    seen = set()
    while True:
        if mount in seen or len(seen) >= MAX_MOUNT_HOPS:
            return None
        seen.add(mount)
        inner = dentry_parts(reader, el, dentry, reader.ptr(mount + el["mount.mnt"] + el["vfsmount.mnt_root"]))
        if inner is None or len(parts) + len(inner) > MAX_PATH_PARTS:
            return None
        parts += inner
        parent = reader.ptr(mount + el["mount.mnt_parent"])
        if not parent or parent == mount:
            return join_path("/", parts)
        dentry = reader.ptr(mount + el["mount.mnt_mountpoint"])
        mount = parent


def first_alias(reader: SafeReader, el: EcryptfsLayout, inode: int) -> Optional[int]:
    node = reader.ptr(inode + el["inode.i_dentry"] + el["hlist_head.first"])
    return container_of(node, el["dentry.d_u.d_alias"]) if node else None


def key_sigs(reader: SafeReader, el: EcryptfsLayout, crypt_stat: int) -> List[str]:
    head = crypt_stat + el["ecryptfs_crypt_stat.keysig_list"]
    sigs = []
    for item in iter_list(reader, head, el["ecryptfs_key_sig.crypt_stat_list"], MAX_KEYSIGS):
        sig = reader.inline_string(item + el["ecryptfs_key_sig.keysig"], ECRYPTFS_SIG_SIZE_HEX + 1)
        if sig:
            sigs.append(sig)
    return sigs


@dataclass
class AuthTok:
    sig: str
    flags: int
    key_address: int
    serial: Optional[int] = None
    status: str = "n/a"  # linux.keyring's status of the key (proven = FEKEK signature matches)
    fekek: Optional[bytes] = None  # the decoded FEKEK (session_key_encryption_key[:key_bytes])

    def describe(self) -> str:
        kind = "fnek" if self.flags & ECRYPTFS_AUTH_TOK_FNEK else "fekek"
        state = "invalid" if self.flags & ECRYPTFS_AUTH_TOK_INVALID else self.status
        serial = ("key %d" % self.serial) if self.serial is not None else "no key"
        return "%s %s (%s, keyring %s)" % (self.sig, kind, serial, state)


def mount_auth_toks(reader: SafeReader, el: EcryptfsLayout, kl: keyring.KeyLayout,
                    sb_info: int, key_guessed: Sequence[str] = ()) -> List[AuthTok]:
    """The mount's global auth tokens; each key decoded as ``linux.keyring`` decodes it."""
    head = (sb_info + el["ecryptfs_sb_info.mount_crypt_stat"]
            + el["ecryptfs_mount_crypt_stat.global_auth_tok_list"])
    toks = []
    for item in iter_list(reader, head, el["ecryptfs_global_auth_tok.mount_crypt_stat_list"], MAX_AUTH_TOKS):
        sig = reader.inline_string(item + el["ecryptfs_global_auth_tok.sig"], ECRYPTFS_SIG_SIZE_HEX + 1)
        tok = AuthTok(sig or "?", reader.u32(item + el["ecryptfs_global_auth_tok.flags"]) or 0,
                      reader.ptr(item + el["ecryptfs_global_auth_tok.global_auth_tok_key"]) or 0)
        _attach_key(reader, kl, tok, key_guessed)
        toks.append(tok)
    return toks


def _attach_key(reader: SafeReader, kl: keyring.KeyLayout, tok: AuthTok, key_guessed: Sequence[str]) -> None:
    record = keyring.read_key(reader, kl, tok.key_address) if tok.key_address else None
    if record is None:
        return
    tok.serial = record.serial
    if record.type_name not in ("user", "logon"):
        tok.status = "not an ecryptfs auth_tok (%s)" % record.type_name
        return
    keyring.decode_user_payload(reader, kl, record)
    if not keyring.decode_ecryptfs(kl, record):
        tok.status = "not an ecryptfs auth_tok (%s)" % record.type_name
        return
    tok.status, tok.fekek = record.status, record.secret
    if tok.status == keyring.PROVEN and key_guessed:
        tok.status = "unverified:guessed-key-offsets"
    if record.description != tok.sig:
        tok.status += ":description-differs"


def csv_field(text: str) -> str:
    """RFC 4180 quoting (the ``csv`` module is not on the vol3plugins import allowlist)."""
    if any(c in text for c in ',"\r\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def tag3_with_auth_toks(header: bytes, toks: Sequence[AuthTok], fek: bytes) -> Tuple[str, str]:
    """``tag3_check`` against every mount FEKEK: pass names the FEKEK that unwraps the header."""
    keyed = [t for t in toks if t.fekek]
    if not keyed:
        return "n/a", "tag-3 n/a: no FEKEK decoded from the mount auth tokens"
    results = [(t, tag3_check(header, t.fekek or b"", fek)) for t in keyed]
    for tok, (status, detail) in results:
        if status == "pass":
            return status, detail if tok.sig in detail else "%s with FEKEK %s" % (detail, tok.sig)
    failed = [tok.sig for tok, (status, _detail) in results if status == "fail"]
    if failed:
        return "fail", "tag-3 unwrapped with FEKEK %s != FEK" % ",".join(failed)
    return results[0][1]


# --------------------------------------------------------------------------- records


@dataclass
class Mount:
    superblock: int
    sb_info: int
    device: str
    mountpoint: Optional[str]
    mount: Optional[int]
    root: Optional[int]  # the mount's root dentry
    lower_dev: str
    auth_toks: List[AuthTok] = field(default_factory=list)


@dataclass
class FileRecord:
    mount: Mount
    inode: int
    ino: int
    size: int
    path: Optional[str]
    lower_inode: int
    lower_ino: Optional[int]
    lower_path: Optional[str]
    crypt_stat: Optional[CryptStat]
    key_sigs: List[str]
    verdict: FekVerdict


class Ecryptfs(interfaces.plugins.PluginInterface):
    """Lists eCryptfs files and recovers each per-file encryption key (FEK), proven from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.ChoiceRequirement(
                name="export", choices=["json", "fek", "fekek"], optional=True,
                description="Write ecryptfs.json (one entry per file, keys included), ecryptfs_fek.csv "
                            "(proven FEKs) or ecryptfs_fekek.txt (keyring-proven FEKEKs)"),
            requirements.BooleanRequirement(
                name="no_schedule", optional=True, default=False,
                description="Skip the second proof (AES key schedule in crypt_stat->tfm)"),
            btf_layouts.btf_method_requirement(),
        ]

    # ------------------------------------------------------------------ setup

    def _setup(self) -> None:
        self.vmlinux, self.layer, self.reader = kernel_reader(self.context, self.config["kernel"])
        self.byteorder = self.reader.byteorder
        self.arch = arch_of(self.layer)
        self.el = EcryptfsLayout.from_module(self.vmlinux, self._btf_structs())
        self.kl = keyring.KeyLayout.from_module(self.vmlinux)
        self.key_guessed = self._auth_tok_guessed()
        self.crypto = KernelLayout.from_module(self.vmlinux)
        self.pc = PagecacheLayout.from_module(self.vmlinux)
        self.phys = SafeReader(self.context.layers[self.layer.config["memory_layer"]])
        self.page_to_phys = pagecache.make_page_to_phys(
            page_object=lambda a: self.vmlinux.object("page", offset=a, absolute=True))
        if self.el.guessed():
            vollog.warning("ISF lacks %d eCryptfs/VFS offsets or sizes, guessed from the LP64 6.8 layout "
                           "(no FEK will be labelled proven): %s", len(self.el.guessed()),
                           ", ".join(self.el.guessed()))
        if self.key_guessed:
            vollog.warning("guessed key/auth-token offsets: no auth token reported keyring-proven: %s",
                           ", ".join(self.key_guessed))

    def _auth_tok_guessed(self) -> List[str]:
        guessed = [k for k in self.kl.defaulted() if k.startswith(AUTH_TOK_KEY_PREFIXES)]
        try:
            self.vmlinux.get_type("ecryptfs_auth_tok")
        except (exceptions.SymbolError, AttributeError):
            guessed.append("sizeof(ecryptfs_auth_tok)")
        return guessed

    def _btf_structs(self) -> Dict[str, Any]:
        """eCryptfs struct layouts from the ``ecryptfs`` module BTF, only when the ISF lacks them."""
        try:
            self.vmlinux.get_type("ecryptfs_crypt_stat")
            return {}
        except (exceptions.SymbolError, AttributeError):
            pass
        recovered = btf_layouts.recover_trusted(self.context, self.config.get("kernel"), FS_TYPE_NAME,
                                                ECRYPTFS_TYPES, self.config.get("btf_method"))
        return dict(recovered.structs) if recovered is not None else {}

    def _symbol_address(self, name: str) -> Optional[int]:
        """Absolute, canonical address (comparable with pointers read from memory)."""
        return symbol_address(self.vmlinux, name, self.layer)

    # ------------------------------------------------------------------ mounts

    def _superblocks(self) -> Iterator[int]:
        head = self._symbol_address("super_blocks")
        if head is None:
            vollog.warning("super_blocks not in the symbol table: nothing to walk")
            return iter(())
        return iter_list(self.reader, head, self.el["super_block.s_list"], MAX_SUPERBLOCKS)

    def _is_ecryptfs(self, sb: int, fs_type: Optional[int]) -> bool:
        s_type = self.reader.ptr(sb + self.el["super_block.s_type"])
        if not s_type:
            return False
        if fs_type is not None:
            return s_type == fs_type
        name = self.reader.ptr(s_type + self.el["file_system_type.name"])
        return self.reader.cstring(name, 64) == FS_TYPE_NAME

    def _mounts(self) -> List[Mount]:
        fs_type = self._symbol_address("ecryptfs_fs_type")
        superblocks = list(self._superblocks())
        mounts = [self._mount(sb) for sb in superblocks if self._is_ecryptfs(sb, fs_type)]
        vollog.info("%d eCryptfs superblocks of %d (fs type %s)", len(mounts), len(superblocks),
                    "ecryptfs_fs_type @%#x" % fs_type if fs_type is not None else "by name")
        return mounts

    def _mount(self, sb: int) -> Mount:
        r, el = self.reader, self.el
        sb_info = r.ptr(sb + el["super_block.s_fs_info"]) or 0
        lower_sb = r.ptr(sb_info + el["ecryptfs_sb_info.wsi_sb"]) if sb_info else None
        mount = next(iter_list(r, sb + el["super_block.s_mounts"], el["mount.mnt_instance"], 64), None)
        root = mountpoint = devname = None
        if mount:
            root = r.ptr(mount + el["mount.mnt"] + el["vfsmount.mnt_root"])
            mountpoint = self._mount_root_path(mount)
            devname = r.cstring(r.ptr(mount + el["mount.mnt_devname"]), 4096)
        lower = r.inline_string(lower_sb + el["super_block.s_id"], el.sizes["super_block.s_id"]) if lower_sb else ""
        toks = mount_auth_toks(r, el, self.kl, sb_info, self.key_guessed) if sb_info else []
        return Mount(sb, sb_info, devname or "?", mountpoint, mount, root, lower or "?", toks)

    def _mount_root_path(self, mount: int) -> Optional[str]:
        """Path of a mount's root, resolved once per mount."""
        cache = self.__dict__.setdefault("_mount_paths", {})
        if mount not in cache:
            root = self.reader.ptr(mount + self.el["mount.mnt"] + self.el["vfsmount.mnt_root"])
            cache[mount] = mount_path(self.reader, self.el, root, mount) if root else None
        return cache[mount]

    # ------------------------------------------------------------------ files

    def _records(self, mount: Mount) -> Iterator[FileRecord]:
        skipped = unreadable_run = 0
        for inode in iter_list(self.reader, mount.superblock + self.el["super_block.s_inodes"],
                               self.el["inode.i_sb_list"], MAX_INODES):
            address = crypt_stat_address(self.el, inode)
            cs = parse_crypt_stat(self.reader.read(address, self.el.sizes["ecryptfs_crypt_stat"]),
                                  address, self.el, self.byteorder, self.reader.pointer_size)
            unreadable_run = unreadable_run + 1 if cs is None else 0
            if unreadable_run > MAX_UNREADABLE_RUN:
                yield self._unreadable_run(mount, inode)
                return
            if cs is not None and not cs.looks_used():
                skipped += 1
                continue
            yield self._record(mount, inode, cs)
        vollog.info("%s: %d inodes without a FEK (directories, unopened files) skipped",
                    mount.mountpoint or mount.device, skipped)

    def _unreadable_run(self, mount: Mount, inode: int) -> FileRecord:
        vollog.warning("%s: more than %d consecutive unreadable crypt_stats: walk of this mount stopped",
                       mount.mountpoint or mount.device, MAX_UNREADABLE_RUN)
        verdict = FekVerdict(ERROR_UNREADABLE_RUN, "more than %d consecutive unreadable crypt_stats: walk "
                             "of this mount stopped" % MAX_UNREADABLE_RUN)
        return FileRecord(mount, inode, 0, 0, None, 0, None, None, None, [], verdict)

    def _record(self, mount: Mount, inode: int, cs: Optional[CryptStat]) -> FileRecord:
        r, el = self.reader, self.el
        lower_inode = r.ptr(container_of(inode, el["ecryptfs_inode_info.vfs_inode"])
                            + el["ecryptfs_inode_info.wii_inode"]) or 0
        dentry = first_alias(r, el, inode)
        verdict = decide(cs, self._schedule(cs), self.el.guessed(), self._tag3(mount, lower_inode, cs))
        return FileRecord(
            mount=mount, inode=inode, ino=r.u64(inode + el["inode.i_ino"]) or 0,
            size=r.u64(inode + el["inode.i_size"]) or 0, path=self._upper_path(mount, dentry),
            lower_inode=lower_inode,
            lower_ino=r.u64(lower_inode + el["inode.i_ino"]) if lower_inode else None,
            lower_path=self._lower_path(dentry), crypt_stat=cs,
            key_sigs=key_sigs(r, el, cs.address) if cs else [], verdict=verdict)

    def _upper_path(self, mount: Mount, dentry: Optional[int]) -> Optional[str]:
        if not dentry or mount.mountpoint is None:
            return None
        parts = dentry_parts(self.reader, self.el, dentry, mount.root)
        return join_path(mount.mountpoint, parts) if parts is not None else None

    def _lower_path(self, dentry: Optional[int]) -> Optional[str]:
        r, el = self.reader, self.el
        info = r.ptr(dentry + el["dentry.d_fsdata"]) if dentry else None
        if not info:
            return None
        lower_path = info + el["ecryptfs_dentry_info.lower_path"]
        vfsmount = r.ptr(lower_path + el["path.mnt"])
        lower_dentry = r.ptr(lower_path + el["path.dentry"])
        if not vfsmount or not lower_dentry:
            return None
        lower_mount = container_of(vfsmount, el["mount.mnt"])
        base = self._mount_root_path(lower_mount)
        parts = dentry_parts(r, el, lower_dentry, r.ptr(vfsmount + el["vfsmount.mnt_root"]))
        return join_path(base, parts) if base is not None and parts is not None else None

    def _schedule(self, cs: Optional[CryptStat]) -> Tuple[str, str]:
        if cs is None or self.config.get("no_schedule") or key_unusable(cs):
            return "n/a", ""
        if any(k.startswith("crypto_") for k in self.crypto.defaulted()):
            return schedule_check(None, cs)  # a guessed crypto_tfm layout never adds a proof
        tfm = read_tfm(self.reader, self.crypto, cs.tfm + self.crypto["crypto_skcipher.base"]) if cs.tfm else None
        if tfm is None:
            return schedule_check(None, cs)
        schedules = collect_schedules(self.reader, self.crypto, tfm, self.byteorder)
        return schedule_check([s.key for s in schedules], cs)

    def lower_header(self, lower_inode: int) -> Optional[bytes]:
        """Page 0 of the lower inode from the page cache (owned pages only), else None."""
        mapping = self.reader.ptr(lower_inode + self.pc["inode.i_mapping"]) if lower_inode else None
        if not mapping:
            return None
        phys = pagecache.mapping_page(self.reader, self.pc, mapping, 0, self.page_to_phys, check_mapping=True)
        return self.phys.read(phys, PAGE_SIZE) if phys is not None else None

    def _tag3(self, mount: Mount, lower_inode: int, cs: Optional[CryptStat]) -> Tuple[str, str]:
        if cs is None or key_unusable(cs):
            return "n/a", ""
        header = self.lower_header(lower_inode)
        if header is None:
            return "n/a", "tag-3 n/a: " + NOT_RESIDENT
        status, detail = tag3_with_auth_toks(header, mount.auth_toks, cs.key)
        guessed = self.pc.defaulted()
        if status == "fail" and guessed:  # a wrong page is no evidence against the key
            return "n/a", detail + " on guessed page-cache offsets (%s)" % ", ".join(guessed)
        return status, detail

    # ------------------------------------------------------------------ output

    def _offsets_label(self) -> str:
        guessed = self.el.guessed()
        return self.el.source() + ("; guessed: %s" % ", ".join(guessed) if guessed else "")

    def _row(self, rec: FileRecord) -> Tuple:
        na = renderers.NotApplicableValue()
        cs = rec.crypt_stat
        key = cs.key if cs else b""
        return (
            rec.mount.mountpoint or na, rec.mount.device, format_hints.Hex(rec.mount.superblock),
            rec.ino, rec.path or na, rec.size,
            rec.lower_ino if rec.lower_ino is not None else na,
            format_hints.Hex(rec.lower_inode), rec.lower_path or na,
            cs.cipher if cs else na, cs.key_size if cs else na,
            key.hex() if any(key) else na,
            ",".join(rec.key_sigs) or na,
            self._auth_tok_text(rec) or na,
            rec.verdict.proven, rec.verdict.detail, self._offsets_label(),
            format_hints.Hex(cs.address if cs else crypt_stat_address(self.el, rec.inode)),
        )

    @staticmethod
    def _auth_tok_text(rec: FileRecord) -> str:
        """The mount's auth tokens; a tag-3 that no mount FEKEK unwraps flags the pairing."""
        text = "; ".join(t.describe() for t in rec.mount.auth_toks)
        if rec.verdict.tag3 == "fail" and text:
            text += "; FEKEK pairing NOT confirmed (tag-3 of this file)"
        return text

    @staticmethod
    def _columns() -> List[Tuple[str, Any]]:
        return [("Mount", str), ("Source", str), ("Superblock", format_hints.Hex), ("Inode", int),
                ("Path", str), ("Size", int), ("LowerInode", int), ("LowerInodeAddr", format_hints.Hex),
                ("LowerPath", str), ("Cipher", str), ("KeySize", int), ("KeyHex", str),
                ("KeySigs", str), ("MountAuthTok", str), ("Proven", str), ("Detail", str),
                ("Offsets", str), ("CryptStat(V)", format_hints.Hex)]

    def _json_report(self, records: List[FileRecord]) -> Dict[str, Any]:
        files = []
        for rec in records:
            cs = rec.crypt_stat
            files.append({
                "mount": rec.mount.mountpoint, "source": rec.mount.device,
                "superblock": rec.mount.superblock, "inode": rec.inode, "ino": rec.ino, "path": rec.path,
                "lower_inode": rec.lower_inode, "lower_ino": rec.lower_ino, "lower_path": rec.lower_path,
                "lower_dev": rec.mount.lower_dev, "cipher": cs.cipher if cs else None,
                "key_size": cs.key_size if cs else None,
                "key_hex": cs.key.hex() if cs and any(cs.key) else None,
                "flags": cs.flags if cs else None, "key_sigs": rec.key_sigs,
                "mount_auth_toks": [{"sig": t.sig, "serial": t.serial, "keyring_status": t.status,
                                     "flags": t.flags} for t in rec.mount.auth_toks],
                "proven": rec.verdict.proven, "root_iv": rec.verdict.root_iv,
                "tfm_schedule": rec.verdict.schedule, "detail": rec.verdict.detail,
                "crypt_stat": cs.address if cs else None, "tag3": rec.verdict.tag3,
            })
        return {"plugin": "linux.ecryptfs", "arch": self.arch, "offsets": self._offsets_label(),
                "offset_sources": dict(sorted(self.el.sources.items())),
                "size_sources": dict(sorted(self.el.size_sources.items())),
                "auth_tok_guessed": list(self.key_guessed),
                "pagecache_offset_sources": dict(sorted(self.pc.sources.items())), "files": files}

    @staticmethod
    def fek_csv(records: Sequence[FileRecord]) -> str:
        """``lower_path,inode,cipher,fek_hex`` for every proven FEK (``inode`` = lower inode number)."""
        lines = ["lower_path,inode,cipher,fek_hex"]
        for rec in records:
            cs = rec.crypt_stat
            if cs is not None and rec.verdict.proven.startswith("oracle:"):
                fields = [rec.lower_path or "", "" if rec.lower_ino is None else str(rec.lower_ino),
                          cs.cipher, cs.key.hex()]
                lines.append(",".join(csv_field(f) for f in fields))
        return "".join(line + "\n" for line in lines)

    @staticmethod
    def fekek_lines(records: Sequence[FileRecord]) -> str:
        """``<sig> <fekek_hex>`` per mount auth token whose FEKEK linux.keyring proves (sig = SHA-512)."""
        seen: Dict[str, str] = {}
        for rec in records:
            for tok in rec.mount.auth_toks:
                if tok.fekek and tok.status == keyring.PROVEN and not tok.flags & ECRYPTFS_AUTH_TOK_INVALID:
                    seen.setdefault(tok.sig, tok.fekek.hex())
        return "".join("%s %s\n" % item for item in sorted(seen.items()))

    def _export(self, records: List[FileRecord]) -> None:
        mode = self.config.get("export")
        if mode == "json":
            with self.open("ecryptfs.json") as handle:
                handle.write(json.dumps(self._json_report(records), indent=1).encode("utf-8"))
        elif mode == "fek":
            write_text(self, "ecryptfs_fek.csv", self.fek_csv(records))
        elif mode == "fekek":
            write_text(self, "ecryptfs_fekek.txt", self.fekek_lines(records))

    def _collect(self) -> List[FileRecord]:
        records: List[FileRecord] = []
        for mount in self._mounts():
            records.extend(self._records(mount))
        return records

    def run(self) -> renderers.TreeGrid:
        self._setup()
        records = self._collect()
        proven = sum(1 for r in records if r.verdict.proven.startswith("oracle:"))
        vollog.info("linux.ecryptfs: %d files with a FEK, %d proven (%s)", len(records), proven, self.arch)
        self._export(records)
        return renderers.TreeGrid(self._columns(), ((0, self._row(r)) for r in records))
