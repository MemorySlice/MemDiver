"""``linux.dmcrypt`` -- active dm-crypt devices and their volume keys, proven from memory alone.

Walk
----
``name_rb_tree`` (fallback ``_minor_idr``) -> ``hash_cell`` -> ``mapped_device.map`` ->
``dm_table.targets[]`` -> every ``dm_target`` whose ``type->name == "crypt"`` ->
``dm_target.private`` = ``struct crypt_config``.  The dm core types come from the vmlinux ISF;
``crypt_config`` is a module type, so its offsets come from ``--offsets`` or the built-in
``secrets.offsets.DM_CRYPT_OFFSETS`` table, and every candidate must pass a self-validating
locator (dm_dev name ``major:minor``, a cipher string dm-crypt would accept, a plausible
key size / key parts / sector size, and ``tfms[0]``'s ``crypto_alg.cra_name`` equal to the
crypto-API name the cipher string parses to).

Key recovery and proof
----------------------
* The key is rebuilt from the AES key schedules (``struct crypto_aes_ctx``) inside the
  transform context: a driver layout table (``AES_CTX_LAYOUTS``) first, then a bounded
  schedule scan of the context and of the transforms it points to (templates such as
  ``xts(aes)`` / ``essiv(...)`` / simd->cryptd wrappers keep their keys one hop away).
* **O1** (always): every key part's full ``key_enc || key_dec || key_length`` must equal what
  ``aes.kernel_crypto_aes_ctx()`` builds from it.  A zeroed context can never pass (the
  schedule of the all-zero key is not zero).
* **O2** (when a LUKS header is resident): the physical layer is scanned for LUKS headers
  (only when a LUKS device with a recovered key exists), a header binds to a device by UUID
  (``hash_cell.uuid`` = ``CRYPT-LUKS<n>-<uuid without dashes>-<name>``) and
  ``luks.verify_volume_key()`` recomputes the PBKDF2 digest.  LUKS2 JSON areas that are not
  physically contiguous with their binary header are re-paired by the header checksum.
* ``Source`` says where the raw key bytes were found: ``crypt_config.key`` (the tail of the
  allocation; wiped when the key came from the kernel keyring) or ``tfm-schedule``.
"""

import hashlib
import json
import logging
import re
import struct
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

from . import btf_layouts
from .kernel_common import (IsfLayout, SafeReader, align_up, arch_of, find_module, isf_offset, isf_size,
                            iter_rb_nodes as _iter_rb, kernel_reader, kernel_release, module_symbol, nonzero,
                            symbol_address)
from .secrets import aes, btf_memory, fsmagic, luks, pagecache
from .secrets import offsets as dm_offsets

vollog = logging.getLogger(__name__)

CIPHER_STRING_RE = re.compile(r"^(capi:)?[a-z0-9]+(-[a-z0-9:()]+)+$")
DEV_NAME_RE = re.compile(r"^[0-9]{1,4}:[0-9]{1,7}$")
PLAUSIBLE_KEY_SIZES = frozenset({16, 24, 32, 48, 64, 96})
PLAUSIBLE_KEY_PARTS = frozenset({1, 2, 3})
PLAUSIBLE_SECTOR_SIZES = frozenset({512, 1024, 2048, 4096})
MAX_TFMS = 64
MAX_TARGETS = 1024
MAX_DEVICES = 4096
CTX_SCAN_LIMIT = 2048  # bytes of a transform context searched for key schedules
CTX_POINTER_SLOTS = 8  # leading pointer-sized words of a context followed to inner transforms
MAX_TFM_DEPTH = 5
AES_CTX_SIZE = 484  # struct crypto_aes_ctx
LUKS2_JSON_START = b'{"keyslots":{'
LUKS_SCAN_NEEDLES = (luks.LUKS_MAGIC, luks.LUKS2_SECONDARY_MAGIC, LUKS2_JSON_START)
MAX_LUKS_CANDIDATES = 256
MAX_LUKS_PAIRINGS = 4096  # LUKS2 header x JSON-page checksum attempts per scan
PAGE = 4096

# dm-crypt ``crypt_status()`` feature words, in emission order, keyed by their flag bit name.
_FEATURE_FLAGS = (
    ("DM_CRYPT_SAME_CPU", "same_cpu_crypt"),
    ("DM_CRYPT_HIGH_PRIORITY", "high_priority"),
    ("DM_CRYPT_NO_OFFLOAD", "submit_from_crypt_cpus"),
    ("DM_CRYPT_NO_READ_WORKQUEUE", "no_read_workqueue"),
    ("DM_CRYPT_NO_WRITE_WORKQUEUE", "no_write_workqueue"),
)


# --------------------------------------------------------------------------- kernel layout


_LP64_DEFAULTS = {  # 6.8 LP64 offsets, used only when the ISF lacks a type
    "rb_node.rb_right": 8, "rb_node.rb_left": 16,
    "hash_cell.name_node": 0, "hash_cell.name": 56, "hash_cell.uuid": 64, "hash_cell.md": 72,
    "mapped_device.map": 80, "mapped_device.name": 168, "mapped_device.disk": 184,
    "mapped_device.interface_ptr": 352,
    "dm_table.num_targets": 208, "dm_table.targets": 224,
    "dm_target.type": 8, "dm_target.begin": 16, "dm_target.len": 24,
    "dm_target.num_discard_bios": 40, "dm_target.private": 56,
    "target_type.name": 8, "dm_dev.bdev": 0, "dm_dev.name": 28,
    "block_device.bd_disk": 16, "gendisk.disk_name": 12,
    "crypto_skcipher.base": 8, "crypto_tfm.__crt_alg": 24, "crypto_tfm.__crt_ctx": 32,
    "crypto_alg.cra_ctxsize": 40, "crypto_alg.cra_name": 56, "crypto_alg.cra_driver_name": 184,
}
_LP64_SIZES = {"dm_target": 80, "dm_dev.name": 16, "gendisk.disk_name": 32,
               "mapped_device.name": 16, "crypto_alg.cra_name": 128}


# Offsets the device-mapper walk needs: without them there is nothing to walk.
WALK_TYPES = ("rb_node", "hash_cell", "mapped_device", "dm_table", "dm_target", "target_type")
# Offsets on the key path: a guessed one here must never yield a "proven" label.
KEY_PATH_KEYS = frozenset({
    "crypto_skcipher.base", "crypto_tfm.__crt_alg", "crypto_tfm.__crt_ctx",
    "crypto_alg.cra_ctxsize", "crypto_alg.cra_name", "crypto_alg.cra_driver_name",
    "dm_target.private", "dm_dev.name", "dm_dev.bdev",
})


@dataclass
class KernelLayout(IsfLayout):
    """vmlinux struct offsets the walk needs (``"type.member" -> offset``) and a few sizes.

    ``sources[key]`` is ``isf`` (vmlinux symbol table), ``table`` (``dm_core`` of the offset
    table / ``--offsets``) or ``default`` (the LP64 6.8 guess).  A bare ``KernelLayout()`` (unit
    tests) has no sources and counts as fully known.
    """

    offsets: Dict[str, int] = field(default_factory=lambda: dict(_LP64_DEFAULTS))
    sizes: Dict[str, int] = field(default_factory=lambda: dict(_LP64_SIZES))

    @classmethod
    def from_module(cls, module: Any, dm_core: Optional[Dict[str, int]] = None,
                    dm_core_source: str = "table") -> "KernelLayout":
        layout, dm_core = cls(), dm_core or {}
        layout.resolve(lambda key: isf_offset(module, *key.split(".", 1)),
                       lambda key: (dm_core[key], dm_core_source) if key in dm_core else None)
        for key in list(layout.sizes):
            size = isf_size(module, key)
            if size is None:
                size = dm_core.get("sizeof(%s)" % key)
            if size is not None:
                layout.sizes[key] = size
        return layout

    def missing_walk(self) -> List[str]:
        """Walk offsets that are only guessed: the dm walk is refused when any is."""
        return [k for k in self.defaulted() if k.split(".", 1)[0] in WALK_TYPES]

    def key_path_defaulted(self) -> List[str]:
        return [k for k in self.defaulted() if k in KEY_PATH_KEYS]


# dm core structs read from the ``dm_mod`` module BTF when dm core is a loadable module.
DM_MOD_STRUCTS = ("hash_cell", "mapped_device", "dm_table", "dm_target", "target_type", "dm_dev")


def dm_core_from_layouts(structs: Dict[str, Any]) -> Dict[str, int]:
    """``dm_core`` keys (``"type.member"``, ``"sizeof(...)"``) from ``btf_memory.BtfStruct`` layouts."""
    dm_core: Dict[str, int] = {}
    for key in _LP64_DEFAULTS:
        type_name, member = key.split(".", 1)
        found = structs[type_name].member(member) if type_name in structs else None
        if found is not None and not found.bitfield_size:
            dm_core[key] = found.offset
    for key in _LP64_SIZES:
        type_name, _dot, member = key.partition(".")
        if type_name not in structs:
            continue
        if not member:
            dm_core["sizeof(%s)" % key] = structs[type_name].size
        elif structs[type_name].member(member) is not None and structs[type_name].member(member).size:
            dm_core["sizeof(%s)" % key] = structs[type_name].member(member).size
    return dm_core


def _named_enum(btf: Any, name: str, prefix: str) -> Dict[str, int]:
    """The module's own ``enum name`` whose enumerators all start with ``prefix``.

    A generic name (``flags``) may name several enums; exactly one distinct candidate must
    match, else ``BtfParseError``.
    """
    candidates = [values for values in btf.enums(name, own_only=True)
                  if values and all(key.startswith(prefix) for key in values)]
    distinct = {tuple(sorted(values.items())) for values in candidates}
    if len(distinct) != 1:
        raise btf_memory.BtfParseError("%d enum %s candidates with %s* names" % (len(distinct), name, prefix))
    return dict(candidates[0])


# --------------------------------------------------------------------------- AES schedule oracle


def _first_expansion_word_ok(buf: bytes, offset: int, key_len: int) -> bool:
    """Cheap prefilter: schedule word ``Nk`` = word0 ^ SubWord(RotWord(word Nk-1)) ^ Rcon1."""
    box = aes.SBOX
    last = buf[offset + key_len - 4:offset + key_len]
    nxt = buf[offset + key_len:offset + key_len + 4]
    first = buf[offset:offset + 4]
    if len(nxt) < 4:
        return False
    return (first[0] ^ box[last[1]] ^ 1 == nxt[0] and first[1] ^ box[last[2]] == nxt[1]
            and first[2] ^ box[last[3]] == nxt[2] and first[3] ^ box[last[0]] == nxt[3])


def _le_words(buf: bytes, byteorder: str) -> bytes:
    """Big-endian kernels store each schedule word swapped; normalise to the LE byte image."""
    if byteorder == "little":
        return buf
    usable = len(buf) - len(buf) % 4
    return b"".join(buf[i:i + 4][::-1] for i in range(0, usable, 4))


def o1_ctx_matches(ctx_bytes: Optional[bytes], key: bytes, byteorder: str = "little") -> bool:
    """O1: the 484 bytes at a ``crypto_aes_ctx`` are exactly the kernel ctx built from ``key``."""
    if not ctx_bytes or len(ctx_bytes) < AES_CTX_SIZE or len(key) not in (16, 24, 32):
        return False
    return ctx_bytes[:AES_CTX_SIZE] == aes.kernel_crypto_aes_ctx(key, byteorder)


def o1_enc_matches(ctx_bytes: Optional[bytes], key: bytes, byteorder: str = "little") -> bool:
    """Weaker O1: only the used ``key_enc`` words match (arch code with a different key_dec)."""
    if not ctx_bytes or len(key) not in (16, 24, 32):
        return False
    schedule = aes.expand_key(key)
    return _le_words(ctx_bytes[:len(schedule)], byteorder) == schedule


@dataclass
class Schedule:
    """One AES key schedule found in a transform context."""

    key: bytes
    address: int
    role: str = "?"  # data | tweak | essiv | ?
    full_ctx: bool = False  # O1 on key_enc + key_dec + key_length
    driver: str = ""


def find_aes_schedules(buf: bytes, base: int = 0, byteorder: str = "little",
                       step: int = 4) -> List[Schedule]:
    """Every AES key schedule (``key_enc`` start) in ``buf``; longest key size wins."""
    image = _le_words(buf, byteorder)
    found: List[Schedule] = []
    offset = 0
    while offset + 176 <= len(image):
        hit = _schedule_at(buf, image, offset, byteorder)
        if hit is None:
            offset += step
            continue
        hit.address = base + offset
        found.append(hit)
        offset += AES_CTX_SIZE if hit.full_ctx else len(aes.expand_key(hit.key))
    return found


def _schedule_at(buf: bytes, image: bytes, offset: int, byteorder: str) -> Optional[Schedule]:
    for key_len in (32, 24, 16):
        if not _first_expansion_word_ok(image, offset, key_len):
            continue
        key = image[offset:offset + key_len]
        schedule = aes.expand_key(key)
        if image[offset:offset + len(schedule)] != schedule:
            continue
        return Schedule(key=key, address=offset,
                        full_ctx=o1_ctx_matches(buf[offset:offset + AES_CTX_SIZE], key, byteorder))
    return None


# --------------------------------------------------------------------------- crypto transforms


@dataclass
class TfmInfo:
    base: int  # struct crypto_tfm address
    cra_name: str
    driver: str
    ctx: int
    ctx_size: int


def read_tfm(reader: SafeReader, kl: KernelLayout, tfm_base: int) -> Optional[TfmInfo]:
    """Decode a ``struct crypto_tfm`` (validated by printable crypto-API names)."""
    alg = reader.ptr(tfm_base + kl["crypto_tfm.__crt_alg"]) if tfm_base else None
    if not alg or alg % 4:
        return None
    name_size = kl.sizes.get("crypto_alg.cra_name", 128)
    cra_name = reader.cstring(alg + kl["crypto_alg.cra_name"], name_size)
    driver = reader.cstring(alg + kl["crypto_alg.cra_driver_name"], name_size)
    if not cra_name or not driver or not re.match(r"^[A-Za-z0-9_(),.-]+$", cra_name):
        return None
    ctx_size = reader.u32(alg + kl["crypto_alg.cra_ctxsize"]) or 0
    return TfmInfo(tfm_base, cra_name, driver, tfm_base + kl["crypto_tfm.__crt_ctx"], ctx_size)


def _layout_schedules(reader: SafeReader, tfm: TfmInfo, byteorder: str) -> List[Schedule]:
    entry = dm_offsets.AES_CTX_LAYOUTS.get(tfm.driver)
    if entry is None:
        return []
    alignment, slots = entry
    base = align_up(tfm.ctx, alignment)
    found = []
    for role, offset in slots:
        data = reader.read(base + offset, AES_CTX_SIZE)
        hits = find_aes_schedules(data or b"", base + offset, byteorder)
        if hits and hits[0].address == base + offset:
            hits[0].role, hits[0].driver = role, tfm.driver
            found.append(hits[0])
    return found if len(found) == len(slots) else []


def _scan_schedules(reader: SafeReader, tfm: TfmInfo, byteorder: str) -> List[Schedule]:
    # never read past cra_ctxsize: the neighbouring slab object may be another device's ctx
    size = min(tfm.ctx_size or CTX_SCAN_LIMIT, CTX_SCAN_LIMIT)
    data = reader.read(tfm.ctx, size)
    hits = find_aes_schedules(data or b"", tfm.ctx, byteorder)
    for hit in hits:
        hit.driver = tfm.driver
    return hits


def _inner_tfms(reader: SafeReader, kl: KernelLayout, tfm: TfmInfo) -> Iterator[TfmInfo]:
    """Transforms referenced by the leading pointer words of ``tfm``'s context.

    Never reads past ``cra_ctxsize``: the words after it belong to another allocation.
    """
    for slot in range(min(CTX_POINTER_SLOTS, tfm.ctx_size // reader.pointer_size)):
        pointer = reader.ptr(tfm.ctx + slot * reader.pointer_size)
        if not pointer or pointer % reader.pointer_size:
            continue
        for base_offset in (kl["crypto_skcipher.base"], 0):
            inner = read_tfm(reader, kl, pointer + base_offset)
            if inner is not None:
                yield inner
                break


def collect_schedules(reader: SafeReader, kl: KernelLayout, tfm: TfmInfo,
                      byteorder: str = "little", depth: int = 0,
                      seen: Optional[set] = None) -> List[Schedule]:
    """AES schedules of ``tfm``: driver layout, else ctx scan, else follow inner transforms."""
    seen = set() if seen is None else seen
    if tfm.base in seen or depth > MAX_TFM_DEPTH:
        return []
    seen.add(tfm.base)
    found = _layout_schedules(reader, tfm, byteorder) or _scan_schedules(reader, tfm, byteorder)
    if found:
        return found
    for inner in _inner_tfms(reader, kl, tfm):
        found.extend(collect_schedules(reader, kl, inner, byteorder, depth + 1, seen))
    return found


# --------------------------------------------------------------------------- key assembly


@dataclass
class KeyPart:
    key: bytes = b""
    o1_full: bool = False
    order_known: bool = True
    detail: str = ""


def _essiv_digest(hash_name: Optional[str], key: bytes) -> Optional[bytes]:
    try:
        return hashlib.new(hash_name or "sha256", key).digest()
    except (ValueError, TypeError):
        return None


def assemble_part(schedules: Sequence[Schedule], spec: luks.CipherSpec) -> KeyPart:
    """One transform's key from its schedules, by the cipher spec's chain/IV mode."""
    if not schedules:
        return KeyPart(detail="no AES schedule in tfm context")
    by_role = {s.role: s for s in schedules if s.role != "?"}
    if spec.chainmode == "xts":
        return _assemble_xts(schedules, by_role)
    if spec.ivmode == "essiv":
        return _assemble_essiv(schedules, by_role, spec.ivopts)
    data = by_role.get("data", schedules[0])
    return KeyPart(data.key, data.full_ctx, True, "1 schedule (%s)" % data.driver)


def _assemble_xts(schedules: Sequence[Schedule], by_role: Dict[str, Schedule]) -> KeyPart:
    if "data" in by_role and "tweak" in by_role:
        data, tweak, known = by_role["data"], by_role["tweak"], True
    elif len(schedules) >= 2:
        data, tweak, known = schedules[0], schedules[1], False
    else:
        return KeyPart(detail="xts needs 2 schedules, found %d" % len(schedules))
    if len(data.key) != len(tweak.key):
        return KeyPart(detail="xts halves differ in length")
    return KeyPart(data.key + tweak.key, data.full_ctx and tweak.full_ctx, known,
                   "xts data+tweak (%s)" % data.driver)


def _assemble_essiv(schedules: Sequence[Schedule], by_role: Dict[str, Schedule],
                    hash_name: Optional[str]) -> KeyPart:
    # Roles are only meaningful inside one fused essiv driver ctx: the generic essiv(...) template
    # reaches its data key (cbc child) and its IV key (an "aes" cipher whose own layout calls it
    # "data") through separate transforms, so every non-"essiv" schedule is a data candidate,
    # fused-driver data first, then discovery order (the template's child pointer comes first).
    fused = [s for s in schedules if s.role == "data" and "essiv" in s.driver]
    candidates = fused + [s for s in schedules if s.role != "essiv" and s not in fused]
    if not candidates:
        return KeyPart(detail="essiv: no data-key schedule")
    for data in candidates:
        derived = _essiv_digest(hash_name, data.key)
        essiv = [s for s in schedules if s is not data and derived and s.key == derived[:len(s.key)]]
        if essiv:
            return KeyPart(data.key, data.full_ctx and essiv[0].full_ctx, True,
                           "essiv data + %s(data) IV key (%s)" % (hash_name, data.driver))
    data = candidates[0]
    return KeyPart(data.key, data.full_ctx, bool(fused),
                   "essiv data key, IV-key schedule not matched (%s)" % data.driver)


# --------------------------------------------------------------------------- crypt_config


@dataclass
class CryptConfig:
    address: int
    dev_name: str
    disk_name: str
    start: int
    cipher_string: str
    spec: luks.CipherSpec
    key_string: Optional[str]
    cipher_auth: Optional[str]
    iv_offset: int
    sector_size: int
    tfms: int
    tfms_count: int
    key_size: int
    key_parts: int
    flags: int
    cipher_flags: int
    on_disk_tag_size: int
    key_tail: Optional[bytes]
    tfm_names: List[str] = field(default_factory=list)
    dev: int = 0  # struct dm_dev * (the backing device; O3 follows it to the page cache)


def _cfg_read(reader: SafeReader, address: int, off: Dict[str, int]) -> Optional[Dict[str, Any]]:
    fields = {
        "dev": reader.ptr(address + off["dev"]), "start": reader.u64(address + off["start"]),
        "cipher_string": reader.ptr(address + off["cipher_string"]),
        "cipher_auth": reader.ptr(address + off["cipher_auth"]),
        "key_string": reader.ptr(address + off["key_string"]),
        "iv_offset": reader.u64(address + off["iv_offset"]),
        "sector_size": reader.u16(address + off["sector_size"]),
        "tfms": reader.ptr(address + off["cipher_tfm"]),
        "tfms_count": reader.u32(address + off["tfms_count"]),
        "cipher_flags": reader.ptr(address + off["cipher_flags"]),
        "flags": reader.ptr(address + off["flags"]),
        "key_size": reader.u32(address + off["key_size"]),
        "key_parts": reader.u32(address + off["key_parts"]),
        "on_disk_tag_size": reader.u32(address + off.get("used_tag_size", off.get("on_disk_tag_size", 0))),
    }
    return None if any(v is None for k, v in fields.items()) else fields


def _plausible_numbers(f: Dict[str, Any]) -> Optional[str]:
    if f["key_size"] not in PLAUSIBLE_KEY_SIZES:
        return "key_size %r" % f["key_size"]
    if f["key_parts"] not in PLAUSIBLE_KEY_PARTS:
        return "key_parts %r" % f["key_parts"]
    if f["sector_size"] not in PLAUSIBLE_SECTOR_SIZES:
        return "sector_size %r" % f["sector_size"]
    if not 1 <= f["tfms_count"] <= MAX_TFMS:
        return "tfms_count %r" % f["tfms_count"]
    return None


def _dev_names(reader: SafeReader, kl: KernelLayout, dm_dev: int) -> Tuple[Optional[str], str]:
    name = reader.inline_string(dm_dev + kl["dm_dev.name"], kl.sizes.get("dm_dev.name", 16))
    bdev = reader.ptr(dm_dev + kl["dm_dev.bdev"])
    disk = reader.ptr(bdev + kl["block_device.bd_disk"]) if bdev else None
    disk_name = reader.inline_string(disk + kl["gendisk.disk_name"],
                                     kl.sizes.get("gendisk.disk_name", 32)) if disk else None
    return name, disk_name or ""


def tfm_of(reader: SafeReader, kl: KernelLayout, tfms: int, index: int) -> Optional[TfmInfo]:
    skcipher = reader.ptr(tfms + index * reader.pointer_size)
    return read_tfm(reader, kl, skcipher + kl["crypto_skcipher.base"]) if skcipher else None


def locate_crypt_config(reader: SafeReader, kl: KernelLayout, address: int,
                        off: dm_offsets.DmCryptOffsets) -> Tuple[Optional[CryptConfig], str]:
    """Read and validate a ``crypt_config`` at ``address``; ``(None, why)`` on rejection."""
    member = off.crypt_config
    fields = _cfg_read(reader, address, member)
    if fields is None:
        return None, "unreadable crypt_config fields"
    problem = _plausible_numbers(fields)
    if problem:
        return None, "implausible " + problem
    dev_name, disk_name = _dev_names(reader, kl, fields["dev"]) if fields["dev"] else (None, "")
    if not dev_name or not DEV_NAME_RE.match(dev_name):
        return None, "dm_dev.name %r is not major:minor" % dev_name
    cipher = reader.cstring(fields["cipher_string"], 128)
    if not cipher or not CIPHER_STRING_RE.match(cipher):
        return None, "cipher_string %r rejected" % cipher
    try:
        spec = luks.parse_cipher_spec(cipher, fields["key_size"])
    except ValueError as error:
        return None, "cipher_string %r: %s" % (cipher, error)
    tfm0 = tfm_of(reader, kl, fields["tfms"], 0) if fields["tfms"] else None
    if tfm0 is None or tfm0.cra_name != spec.crypto_api_name:
        return None, "tfms[0] cra_name %r != %r" % (tfm0 and tfm0.cra_name, spec.crypto_api_name)
    tail = reader.read(address + member["key"], fields["key_size"])
    return CryptConfig(
        address=address, dev_name=dev_name, disk_name=disk_name, start=fields["start"],
        cipher_string=cipher, spec=spec, key_string=reader.cstring(fields["key_string"], 256),
        cipher_auth=reader.cstring(fields["cipher_auth"], 128), iv_offset=fields["iv_offset"],
        sector_size=fields["sector_size"], tfms=fields["tfms"], tfms_count=fields["tfms_count"],
        key_size=fields["key_size"], key_parts=fields["key_parts"], flags=fields["flags"],
        cipher_flags=fields["cipher_flags"], on_disk_tag_size=fields["on_disk_tag_size"],
        key_tail=tail, tfm_names=[tfm0.driver], dev=fields["dev"],
    ), "ok"


def probe_crypt_basics(reader: SafeReader, kl: KernelLayout, address: int) -> Dict[str, Optional[str]]:
    """Display-only facts without an offset table: ``dev`` is member 0 in every kernel since
    v2.6, and the cipher string is the first pointer slot (of 64) to a dm-crypt cipher name."""
    dm_dev = reader.ptr(address)
    dev_name, disk_name = _dev_names(reader, kl, dm_dev) if dm_dev else (None, "")
    cipher = None
    for slot in range(0, 64 * reader.pointer_size, reader.pointer_size):
        text = reader.cstring(reader.ptr(address + slot), 128)
        if text and CIPHER_STRING_RE.match(text):
            cipher = text
            break
    valid_dev = bool(dev_name and DEV_NAME_RE.match(dev_name))
    return {"cipher": cipher, "device": "%s (%s)" % (dev_name, disk_name) if valid_dev else None}


def relocate_crypt_config(reader: SafeReader, kl: KernelLayout, address: int,
                          off: dm_offsets.DmCryptOffsets) -> Tuple[Optional[CryptConfig], str]:
    """Locator with drift repair: shift the table by where ``cipher_string`` really is."""
    found, why = locate_crypt_config(reader, kl, address, off)
    if found is not None:
        return found, why
    expected = off.crypt_config["cipher_string"]
    for slot in range(0, 512, reader.pointer_size):
        if slot == expected:
            continue
        text = reader.cstring(reader.ptr(address + slot), 128)
        if not text or not CIPHER_STRING_RE.match(text):
            continue
        delta = slot - expected
        shifted = dm_offsets.DmCryptOffsets(
            {k: v + delta if k != "dev" else v for k, v in off.crypt_config.items()},
            off.flag_bits, off.cipher_flag_bits, source="%s shifted %+d" % (off.source, delta))
        relocated, why2 = locate_crypt_config(reader, kl, address, shifted)
        if relocated is not None:
            vollog.info("crypt_config @%#x: offsets drifted by %+d (cipher_string at %d)",
                        address, delta, slot)
            return relocated, "ok (offsets shifted %+d)" % delta
    return None, why


# --------------------------------------------------------------------------- key recovery


@dataclass
class Recovery:
    key: Optional[bytes]
    source: str
    o1: str  # "O1:schedule" | "O1:key_enc" | ""
    detail: str
    order_known: bool = True
    conflict: bool = False  # crypt_config.key holds a different key than the schedules
    alternates: List[Tuple[bytes, str, str]] = field(default_factory=list)  # (key, source, o1)


def _swap_halves(key: bytes) -> bytes:
    half = len(key) // 2
    return key[half:] + key[:half]


def recover_key(reader: SafeReader, kl: KernelLayout, cfg: CryptConfig,
                byteorder: str = "little") -> Recovery:
    """Rebuild the volume key from all transforms; check it against ``crypt_config.key``."""
    parts: List[KeyPart] = []
    for index in range(cfg.tfms_count):
        tfm = tfm_of(reader, kl, cfg.tfms, index)
        if tfm is None:
            parts.append(KeyPart(detail="tfms[%d] unreadable" % index))
            continue
        parts.append(assemble_part(collect_schedules(reader, kl, tfm, byteorder), cfg.spec))
    return _merge_parts(parts, cfg)


def _merge_parts(parts: List[KeyPart], cfg: CryptConfig) -> Recovery:
    tail = cfg.key_tail if nonzero(cfg.key_tail) else None
    detail = "; ".join(p.detail for p in parts if p.detail)
    if not parts or not all(p.key for p in parts):
        if tail:
            return Recovery(tail, "crypt_config.key", "", detail + "; schedule not recovered")
        return Recovery(None, "", "", detail)
    key = b"".join(p.key for p in parts)
    o1 = "O1:schedule" if all(p.o1_full for p in parts) else "O1:key_enc"
    order_known = all(p.order_known for p in parts)
    xts_single = cfg.spec.chainmode == "xts" and len(parts) == 1
    swapped = [(_swap_halves(key), "tfm-schedule", o1)] if xts_single else []
    if tail is not None and tail == key:
        return Recovery(key, "crypt_config.key", o1, detail, True)
    if tail is not None and swapped and tail == swapped[0][0]:
        return Recovery(tail, "crypt_config.key", o1, detail + "; tail fixed xts half order", True)
    if tail is not None:
        return Recovery(key, "tfm-schedule", o1, detail + "; CONFLICT: crypt_config.key differs",
                        order_known, True, swapped + [(tail, "crypt_config.key", "")])
    return Recovery(key, "tfm-schedule", o1, detail, order_known, False, swapped)


# --------------------------------------------------------------------------- verdict

PROVEN, UNVERIFIED, CONFLICT, REJECTED, NONE = "proven", "unverified", "conflict", "rejected", "none"


O3_NA: Tuple[str, str, str] = ("n/a", "", "")


@dataclass
class Verdict:
    status: str  # proven | unverified | conflict | rejected | none
    oracle: str
    key: Optional[bytes]
    source: str
    o2: Tuple[str, str, Optional[int]] = ("n/a", "", None)
    o3: Tuple[str, str, str] = O3_NA  # (verdict, detail, evidence: filesystem | pagecache-pair)


def proof_label(o1: str, proofs: Sequence[Tuple[str, str]]) -> str:
    """``O1+O2:luks-digest``, ``O1+O3:vfat``, ``O1+O2+O3:luks-digest+ext4``; a weak or absent
    O1 keeps each oracle's own evidence (``O1:key_enc+O2:luks-digest``, ``O3:ext4``)."""
    if o1 == "O1:schedule":
        return "O1+%s:%s" % ("+".join(n for n, _e in proofs), "+".join(e for _n, e in proofs))
    return "+".join(([o1] if o1 else []) + ["%s:%s" % proof for proof in proofs])


def _o2_label(o1: str) -> str:
    return proof_label(o1, [("O2", "luks-digest")])


def _with_o3(verdict: Verdict, o1: str, o3: Optional[Any]) -> Verdict:
    """Run O3 on an O2-proven key: a pass adds its evidence to the label; a fail is only
    reported (O2 is the primary proof)."""
    if o3 is None:
        return verdict
    verdict.o3 = o3(verdict.key)
    if verdict.o3[0] == "pass":
        verdict.oracle = proof_label(o1, [("O2", "luks-digest"), ("O3", verdict.o3[2])])
    return verdict


def _o3_candidates(recovery: Recovery) -> List[Tuple[bytes, str, str]]:
    """The primary key, its alternates and -- XTS order unknown -- its swapped halves."""
    candidates = [(recovery.key, recovery.source, recovery.o1)] + list(recovery.alternates)
    swapped = _swap_halves(recovery.key)
    if not recovery.order_known and all(key != swapped for key, _s, _o in candidates):
        candidates.append((swapped, recovery.source, recovery.o1))
    return candidates


def _decide_o3(recovery: Recovery, o3: Any, o2: Tuple[str, str, Optional[int]]
               ) -> Tuple[Optional[Verdict], Tuple[str, str, str]]:
    """O3 when O2 is n/a: ``(verdict or None, O3 result of the primary key)``.

    A pass for any candidate proves it (this settles the XTS half order); a primary-key
    ``fail`` that no candidate overturns rejects; ``n/a`` decides nothing.
    """
    primary = None
    for key, source, o1 in _o3_candidates(recovery):
        result = o3(key)
        primary = primary or result
        if result[0] == "pass":
            return Verdict(PROVEN, proof_label(o1, [("O3", result[2])]), key, source, o2, result), primary
    if primary[0] == "fail":
        return Verdict(REJECTED, "rejected:pagecache", recovery.key, recovery.source, o2, primary), primary
    return None, primary


def decide(recovery: Optional[Recovery], o2: Optional[Any] = None,
           defaulted_key_path: Sequence[str] = (), o3: Optional[Any] = None) -> Verdict:
    """The single place a key becomes ``proven``.

    proven = O1 passed, no contradicting ``crypt_config.key``, XTS half order settled and the
    LUKS digest (O2) passed or is not applicable -- or O2 itself passed for a candidate -- or,
    O2 not applicable, the page-cache proof (O3) passed for a candidate.  ``o2`` is ``key ->
    (verdict, detail, address)`` (``prove_o2`` bound to a device), ``o3`` is ``key ->
    (verdict, detail, evidence)`` (an ``O3Prover``); either may be None.  O3 never rejects a
    key O2 proved, and ``n/a`` (nothing resident) never rejects anything.
    """
    if recovery is None or not recovery.key:
        return Verdict(NONE, "none", None, "")
    first = o2(recovery.key) if o2 else ("n/a", "", None)
    if first[0] == "pass":
        return _guard(_with_o3(Verdict(PROVEN, _o2_label(recovery.o1), recovery.key, recovery.source, first),
                               recovery.o1, o3), defaulted_key_path)
    if first[0] == "fail":
        for key, source, o1 in recovery.alternates:
            retry = o2(key)
            if retry[0] == "pass":
                return _guard(_with_o3(Verdict(PROVEN, _o2_label(o1), key, source, retry), o1, o3),
                              defaulted_key_path)
        return Verdict(REJECTED, "rejected:luks-digest", recovery.key, recovery.source, first)
    o3_result = O3_NA
    if o3 is not None:
        settled, o3_result = _decide_o3(recovery, o3, first)
        if settled is not None:
            return _guard(settled, defaulted_key_path) if settled.status == PROVEN else settled
    if recovery.conflict:
        return Verdict(CONFLICT, "conflict", recovery.key, recovery.source, first, o3_result)
    if not recovery.o1:
        return Verdict(UNVERIFIED, "unverified", recovery.key, recovery.source, first, o3_result)
    if not recovery.order_known:
        return Verdict(UNVERIFIED, "unverified:xts-order", recovery.key, recovery.source, first, o3_result)
    return _guard(Verdict(PROVEN, recovery.o1, recovery.key, recovery.source, first, o3_result),
                  defaulted_key_path)


def _guard(verdict: Verdict, defaulted_key_path: Sequence[str]) -> Verdict:
    if defaulted_key_path:
        verdict.status, verdict.oracle = UNVERIFIED, "unverified:defaulted-offsets"
    return verdict


# --------------------------------------------------------------------------- O2 (LUKS headers)


def luks_uuid_from_dm(dm_uuid: Optional[str]) -> Optional[str]:
    """``CRYPT-LUKS2-<32 hex>-<name>`` -> the 32 hex digits (lower case), else None."""
    match = re.match(r"^CRYPT-LUKS[12]-([0-9a-fA-F]{32})-", dm_uuid or "")
    return match.group(1).lower() if match else None


def _uuid_key(uuid: str) -> str:
    return uuid.replace("-", "").lower()


@dataclass
class LuksIndex:
    """Parsed LUKS headers found in physical memory, keyed by de-dashed UUID."""

    headers: Dict[str, List[Tuple[int, Any]]] = field(default_factory=dict)
    _verdicts: Dict[Tuple[str, bytes], Any] = field(default_factory=dict, repr=False)

    def add(self, address: int, header: Any) -> None:
        bucket = self.headers.setdefault(_uuid_key(header.uuid), [])
        if all(existing_address != address for existing_address, _ in bucket):
            bucket.append((address, header))

    def verify(self, header: Any, key: bytes) -> Any:
        """``luks.verify_volume_key``, run once per (header content, key): the page-cache and
        buffer copies of one header (and ``decide``'s retries) share one PBKDF2 run."""
        memo = (repr(header), bytes(key))
        if memo not in self._verdicts:
            self._verdicts[memo] = luks.verify_volume_key(header, key)
        return self._verdicts[memo]

    def for_uuid(self, uuid_hex: str) -> List[Tuple[int, Any]]:
        return self.headers.get(uuid_hex, [])


def _luks2_hdr_size(head: bytes) -> int:
    return struct.unpack_from(">Q", head, 8)[0] if len(head) >= 16 else 0


def _luks2_with_json(head: bytes, json_area: Optional[bytes], hdr_size: int) -> Optional[Any]:
    if json_area is None:
        return None
    area = (head[:PAGE] + json_area)[:hdr_size].ljust(hdr_size, b"\0")
    try:
        header = luks.parse_luks2(area)
    except luks.LuksParseError:
        return None
    return header if header.checksum_ok else None


class JsonPages:
    """LUKS2 JSON-area candidates (page-aligned ``{"keyslots":{`` hits), each read once."""

    def __init__(self, read: Any, pages: Sequence[int], max_pairings: int = MAX_LUKS_PAIRINGS) -> None:
        self._read, self.pages, self._cache = read, list(pages), {}
        self.budget = max_pairings  # header x page checksum attempts left, shared by all headers

    def areas(self, page: int, length: int) -> List[bytes]:
        if (page, length) not in self._cache:
            areas = [self._read(page, length), self._read(page, PAGE)]
            self._cache[(page, length)] = [a for a in areas if a is not None]
        return self._cache[(page, length)]


def _header_uuid(head: bytes) -> Optional[str]:
    try:
        return _uuid_key(luks.parse_luks(head).uuid)
    except (luks.LuksParseError, ValueError, struct.error):
        return None


def parse_resident_header(read: Any, address: int, json_pages: Any) -> Optional[Any]:
    """Parse the LUKS header at ``address``; re-pair a LUKS2 JSON area by checksum if needed.

    ``json_pages`` is a ``JsonPages`` (or a plain address list).
    """
    if not isinstance(json_pages, JsonPages):
        json_pages = JsonPages(read, json_pages)
    head = read(address, PAGE)
    if head is None or 0 not in luks.find_luks_headers(head):
        return None
    try:
        header = luks.parse_luks(head)
    except luks.LuksParseError:
        return None
    if isinstance(header, luks.Luks1Header):
        return header
    hdr_size = _luks2_hdr_size(head)
    if hdr_size not in luks.LUKS2_HDR_SIZES:
        return None
    contiguous = _luks2_with_json(head, read(address + PAGE, hdr_size - PAGE), hdr_size)
    if contiguous is not None:
        return contiguous
    for page in json_pages.pages:
        for json_area in json_pages.areas(page, hdr_size - PAGE):
            if json_pages.budget <= 0:
                return None
            json_pages.budget -= 1
            paired = _luks2_with_json(head, json_area, hdr_size)
            if paired is not None:
                return paired
    return None


def build_luks_index(read: Any, hits: Sequence[Tuple[int, bytes]],
                     wanted: Optional[Sequence[str]] = None) -> LuksIndex:
    """Turn scanner hits (address, needle) into a ``LuksIndex``.

    With ``wanted`` (de-dashed UUIDs of the devices to prove) only headers of those UUIDs are
    parsed fully -- and none of them is ever dropped by a cap; without it the first
    ``MAX_LUKS_CANDIDATES`` headers are.
    """
    json_pages = JsonPages(read, [a for a, n in hits if n == LUKS2_JSON_START and a % PAGE == 0])
    headers = [a for a, n in hits if n != LUKS2_JSON_START]
    if wanted is None:
        headers = headers[:MAX_LUKS_CANDIDATES]
    else:
        wanted_set = set(wanted)
        headers = [a for a in headers if _header_uuid(read(a, PAGE) or b"") in wanted_set]
    index = LuksIndex()
    for address in headers:
        header = parse_resident_header(read, address, json_pages)
        if header is not None and header.uuid:
            index.add(address, header)
    return index


def prove_o2(index: LuksIndex, dm_uuid: Optional[str], key: bytes) -> Tuple[str, str, Optional[int]]:
    """``(verdict, detail, header address)``: verdict ``pass`` | ``fail`` | ``n/a``.

    ``fail`` needs a header of the device's own UUID that parsed (LUKS2: checksum-valid).
    """
    uuid_hex = luks_uuid_from_dm(dm_uuid)
    if uuid_hex is None:
        return "n/a", "not a LUKS device", None
    candidates = index.for_uuid(uuid_hex)
    if not candidates:
        return "n/a", "no resident LUKS header for this UUID", None
    reasons = []
    for address, header in candidates:
        verdict = index.verify(header, key)
        if verdict.matched:
            return "pass", "digest %s matched (header @%#x)" % (verdict.digest_id, address), address
        reasons.append(verdict.detail)
    return "fail", "; ".join(reasons), candidates[0][0]


# --------------------------------------------------------------------------- O3 (page cache)

LOOP_MAJOR = 7
O3_MAX_PAGE_READS = 8  # page contents read per device (the xarray walk itself is not counted)
O3_MAX_UNITS = 16  # dm-crypt units decrypted per device, over every key candidate
O3_MAX_PAIRS = 4
O3_PLAIN_SCAN = 64  # resident plaintext pages considered for pairing
O3_MIN_BITS = 64  # fsmagic.best_match proof threshold
# vmlinux members O3 follows; any missing one makes O3 ``n/a: layout`` (never a guess: a wrong
# offset could pair the wrong pages and wrongly reject a key)
O3_MEMBERS = ("block_device.bd_disk", "gendisk.major", "gendisk.private_data", "gendisk.part0",
              "file.f_mapping", "inode.i_mapping", "address_space.i_pages", "xarray.xa_head",
              "xa_node.shift", "xa_node.slots", "page.mapping")
O3_BDEV_MAPPING = ("block_device.bd_mapping", "block_device.bd_inode")  # v6.10+ | older
O3_LOOP_MEMBERS = ("loop_device.lo_backing_file", "loop_device.lo_offset")
O3_LOOP_CHECK = "loop_device.lo_disk"  # optional back-pointer check


def o3_layout(offset_of: Callable[[str, str], Optional[int]],
              size_of: Callable[[str], Optional[int]]) -> Dict[str, int]:
    """``"type.member" -> offset`` (and ``sizeof(page)``) of every O3 member the ISF has."""
    layout: Dict[str, int] = {}
    for key in O3_MEMBERS + O3_BDEV_MAPPING + O3_LOOP_MEMBERS + (O3_LOOP_CHECK,):
        offset = offset_of(*key.split(".", 1))
        if offset is not None:
            layout[key] = offset
    size = size_of("page")
    if size:
        layout["sizeof(page)"] = size
    return layout


def o3_missing(layout: Dict[str, int]) -> List[str]:
    """Members O3 needs for any device (the loop members are checked per loop device)."""
    missing = [k for k in O3_MEMBERS + ("sizeof(page)", "dm_dev.bdev") if k not in layout]
    if not any(k in layout for k in O3_BDEV_MAPPING):
        missing.append("block_device.bd_inode|bd_mapping")
    return missing


def bdev_mapping(reader: SafeReader, layout: Dict[str, int], bdev: Optional[int]) -> Optional[int]:
    """The page cache (``address_space``) of a ``block_device``."""
    if not bdev:
        return None
    if "block_device.bd_mapping" in layout:
        return reader.ptr(bdev + layout["block_device.bd_mapping"]) or None
    inode = reader.ptr(bdev + layout["block_device.bd_inode"])
    return (reader.ptr(inode + layout["inode.i_mapping"]) or None) if inode else None


def ciphertext_source(reader: SafeReader, layout: Dict[str, int], cfg: CryptConfig
                      ) -> Tuple[Optional[Tuple[int, int, str]], str]:
    """``((mapping, byte_base, label), why)``: the page cache holding the target's ciphertext.

    A loop device (major 7) caches its BACKING FILE (``lo_backing_file->f_mapping``, the device
    starting at ``lo_offset``); any other device its own bdev mapping.  Target sector ``s`` is
    at byte ``byte_base + 512 * s`` of the mapping.
    """
    bdev = reader.ptr(cfg.dev + layout["dm_dev.bdev"]) if cfg.dev else None
    disk = reader.ptr(bdev + layout["block_device.bd_disk"]) if bdev else None
    major = reader.u32(disk + layout["gendisk.major"]) if disk else None
    if major is None:
        return None, "backing device unreadable"
    if major != LOOP_MAJOR:
        mapping = bdev_mapping(reader, layout, bdev)
        return ((mapping, cfg.start * 512, "bdev"), "ok") if mapping else (None, "bdev mapping unreadable")
    missing = [k for k in O3_LOOP_MEMBERS if k not in layout]
    if missing:
        return None, "layout: " + ", ".join(missing)
    loop = reader.ptr(disk + layout["gendisk.private_data"])
    if loop and O3_LOOP_CHECK in layout and pagecache.canonical_address(
            reader.ptr(loop + layout[O3_LOOP_CHECK]) or 0) != pagecache.canonical_address(disk):
        return None, "loop_device.lo_disk does not point back to its gendisk"
    backing = reader.ptr(loop + layout["loop_device.lo_backing_file"]) if loop else None
    mapping = reader.ptr(backing + layout["file.f_mapping"]) if backing else None
    lo_offset = reader.u64(loop + layout["loop_device.lo_offset"]) if loop else None
    if not mapping or lo_offset is None:
        return None, "loop backing file unreadable"
    return (mapping, lo_offset + cfg.start * 512, "loop-backing"), "ok"


def plaintext_source(reader: SafeReader, layout: Dict[str, int], device: "DmDevice") -> Optional[int]:
    """The dm device's own page cache (``gendisk.part0``): resident pages are plaintext."""
    part0 = reader.ptr(device.disk + layout["gendisk.part0"]) if device.disk else None
    return bdev_mapping(reader, layout, part0)


def _looks_random(data: bytes) -> bool:
    """A wrong key decrypts to uniform noise; a right key on a stale page to structured bytes."""
    return data.count(0) <= len(data) // 64 and len(set(data)) >= 0.6 * min(256, len(data))


@dataclass
class O3Pages:
    """Page-cache access: ``lookup(mapping, index)`` -> physical address or None,
    ``iterate(mapping, limit)`` -> ``(index, physical)``, ``read(physical)`` -> one page."""

    lookup: Callable[[int, int], Optional[int]]
    iterate: Callable[[int, int], Iterator[Tuple[int, int]]]
    read: Callable[[int], Optional[bytes]]


class O3Prover:
    """O3 for one crypt target: ``prover(key) -> (verdict, detail, evidence)``.

    Pair mode first: a resident ciphertext unit whose plaintext page is resident on the dm
    device too must decrypt to exactly those bytes (``pagecache-pair``).  Else the first page
    of the target (it must start the device) must decrypt to a filesystem head
    (``fsmagic.best_match``, >= 64 bits).  Resident pairs that all decrypt to noise -> ``fail``;
    nothing resident -> ``n/a`` (never a rejection).  Page reads are shared by every key tried;
    the budgets are per device.
    """

    def __init__(self, pages: O3Pages, cfg: CryptConfig, begin: int, length: int, iv_large: bool,
                 cipher: Optional[Tuple[int, int, str]], plain: Optional[int] = None, why: str = "") -> None:
        self.pages, self.cfg, self.begin, self.length, self.iv_large = pages, cfg, begin, length, iv_large
        self.cipher, self.plain, self.why = cipher, plain, why if cipher is None else ""
        self.reads = self.units = 0
        self.seconds = 0.0  # time spent proving (page walks, reads, decryption)
        self._phys: Dict[int, Optional[int]] = {}
        self._content: Dict[int, Optional[bytes]] = {}
        self._pairs: Optional[List[Tuple[int, bytes, bytes]]] = None
        self._head: Optional[Tuple[Optional[bytes], str]] = None
        if cipher is not None and cfg.on_disk_tag_size:
            self.why = "integrity (AEAD) layout"

    def __call__(self, key: bytes) -> Tuple[str, str, str]:
        if self.why:
            return "n/a", self.why, ""
        started = time.perf_counter()
        try:
            return self._prove(bytes(key))
        except ValueError as error:  # a cipher / key size the dm primitives do not model
            return "n/a", str(error), ""
        finally:
            self.seconds += time.perf_counter() - started

    # ------------------------------------------------------------------ page access

    def _read(self, phys: Optional[int]) -> Optional[bytes]:
        if phys is None:
            return None
        if phys not in self._content:
            if self.reads >= O3_MAX_PAGE_READS:
                return None
            self.reads += 1
            self._content[phys] = self.pages.read(phys)
        return self._content[phys]

    def _cipher_page(self, index: int) -> Optional[int]:
        if index not in self._phys:
            self._phys[index] = self.pages.lookup(self.cipher[0], index)
        return self._phys[index]

    def _cipher_indexes(self, dm_byte: int, length: int) -> range:
        start = self.cipher[1] + dm_byte
        return range(start >> 12, ((start + length - 1) >> 12) + 1)

    def _cipher_bytes(self, dm_byte: int, length: int) -> Optional[bytes]:
        data = b""
        for index in self._cipher_indexes(dm_byte, length):
            page = self._read(self._cipher_page(index))
            if page is None or len(page) != PAGE:
                return None
            data += page
        skip = (self.cipher[1] + dm_byte) & (PAGE - 1)
        return data[skip:skip + length]

    # ------------------------------------------------------------------ evidence (key-independent)

    def _first_page(self) -> Tuple[Optional[bytes], str]:
        """Ciphertext of the target's first page (``fsmagic`` needs bytes 0..0x800)."""
        if self._head is None:
            length = min(PAGE, self.length * 512) // self.cfg.sector_size * self.cfg.sector_size
            missing = [i for i in self._cipher_indexes(0, length) if self._cipher_page(i) is None
                       ] if length and not self.begin else []
            if self.begin:
                self._head = None, "target starts at sector %d, not at the device start" % self.begin
            elif not length:
                self._head = None, "target shorter than one unit"
            elif missing:
                self._head = None, "unit 0 not resident (page idx %d of the %s mapping)" % (
                    missing[0], self.cipher[2])
            else:
                data = self._cipher_bytes(0, length)
                why = "page read budget" if data is None else "unit 0 never written (all-zero)"
                self._head = (data, "") if data is not None and nonzero(data) else (None, why)
        return self._head

    def _pair_candidates(self) -> List[Tuple[int, bytes, bytes]]:
        """Up to ``O3_MAX_PAIRS`` ``(dm_sector, plaintext unit, ciphertext unit)``, both non-zero."""
        if self._pairs is None:
            self._first_page()  # its reads come first: fs-magic must never starve
            self._pairs = []
            for index, phys in self.pages.iterate(self.plain, O3_PLAIN_SCAN) if self.plain else ():
                if len(self._pairs) >= O3_MAX_PAIRS or self.reads >= O3_MAX_PAGE_READS:
                    break
                pair = self._pair_at(index, phys)
                if pair is not None:
                    self._pairs.append(pair)
        return self._pairs

    def _pair_at(self, index: int, phys: int) -> Optional[Tuple[int, bytes, bytes]]:
        dm_byte = index * PAGE - self.begin * 512
        if dm_byte < 0 or dm_byte + PAGE > self.length * 512:
            return None
        if any(self._cipher_page(i) is None for i in self._cipher_indexes(dm_byte, PAGE)):
            return None
        plain = self._read(phys)
        if not plain or not nonzero(plain):
            return None
        cipher = self._cipher_bytes(dm_byte, PAGE)
        size = self.cfg.sector_size
        for unit in range((-dm_byte) % size, PAGE - size + 1, size):
            if cipher and nonzero(plain[unit:unit + size]) and nonzero(cipher[unit:unit + size]):
                return (dm_byte + unit) // 512, plain[unit:unit + size], cipher[unit:unit + size]
        return None

    # ------------------------------------------------------------------ the proof

    def _decrypt(self, key: bytes, dm_sector: int, data: bytes) -> Optional[bytes]:
        size = self.cfg.sector_size
        if self.units + len(data) // size > O3_MAX_UNITS:
            return None
        plain = b""
        for start in range(0, len(data), size):
            iv_sector = aes.dm_iv_sector(dm_sector + start // 512, self.cfg.iv_offset, size, self.iv_large)
            plain += aes.dm_decrypt_unit(key, self.cfg.cipher_string, iv_sector, data[start:start + size])
            self.units += 1
        return plain

    def _prove(self, key: bytes) -> Tuple[str, str, str]:
        noise = 0
        for dm_sector, plain, cipher in self._pair_candidates():
            decrypted = self._decrypt(key, dm_sector, cipher)
            if decrypted is None:
                return "n/a", "unit budget (%d) spent" % O3_MAX_UNITS, ""
            if decrypted == plain:
                return ("pass", "%s unit at dm sector %d decrypts to the resident dm page (%d bytes)"
                        % (self.cipher[2], dm_sector, len(plain)), "pagecache-pair")
            noise += _looks_random(decrypted)
        head, why = self._first_page()
        if head is not None:
            decrypted = self._decrypt(key, 0, head)
            if decrypted is None:
                return "n/a", "unit budget (%d) spent" % O3_MAX_UNITS, ""
            match = fsmagic.best_match({0: decrypted}, O3_MIN_BITS)
            if match is not None:
                return ("pass", "%s unit 0 decrypts to %s (%d bits: %s)"
                        % (self.cipher[2], match.fs, match.bits, match.detail), match.fs)
            why = "unit 0 decrypts to no known filesystem head"
        if noise:
            return "fail", "%d resident page pair(s) decrypt to noise (%s)" % (noise, self.cipher[2]), ""
        return "n/a", why, ""


# --------------------------------------------------------------------------- dmsetup line


def _bit(value: int, bits: Dict[str, int], name: str) -> bool:
    return name in bits and bool(value >> bits[name] & 1)


def dmsetup_line(begin: int, length: int, cfg: CryptConfig, key_hex: Optional[str],
                 num_discard_bios: int, off: dm_offsets.DmCryptOffsets) -> str:
    """The ``dmsetup table --showkeys`` line, as dm-crypt's ``crypt_status()`` emits it."""
    if cfg.key_size == 0:
        key_field = "-"
    elif cfg.key_string:
        key_field = ":%u:%s" % (cfg.key_size, cfg.key_string)
    else:
        key_field = key_hex or "-"
    line = "%d %d crypt %s %s %d %s %d" % (begin, length, cfg.cipher_string, key_field,
                                          cfg.iv_offset, cfg.dev_name, cfg.start)
    features = ["allow_discards"] if num_discard_bios else []
    features += [word for flag, word in _FEATURE_FLAGS if _bit(cfg.flags, off.flag_bits, flag)]
    if cfg.on_disk_tag_size:
        features.append("integrity:%u:%s" % (cfg.on_disk_tag_size, cfg.cipher_auth or ""))
    if cfg.sector_size != 512:
        features.append("sector_size:%d" % cfg.sector_size)
    if _bit(cfg.cipher_flags, off.cipher_flag_bits, "CRYPT_IV_LARGE_SECTORS"):
        features.append("iv_large_sectors")
    if features:
        line += " %d %s" % (len(features), " ".join(features))
    return line


# --------------------------------------------------------------------------- cryptsetup export


def device_type(dm_uuid: Optional[str]) -> str:
    """``luks1`` | ``luks2`` | ``plain`` from the dm UUID cryptsetup set, else ``other``."""
    match = re.match(r"^CRYPT-(LUKS1|LUKS2|PLAIN)-", dm_uuid or "")
    return match.group(1).lower() if match else "other"


def _comment_text(text: str) -> str:
    return "".join(c if " " <= c <= "~" else "?" for c in text)


def cryptsetup_script(name: str, dm_uuid: Optional[str], cfg: CryptConfig, key_file: str,
                      replay_line: str, oracle: str, discards: bool = False, iv_large: bool = False) -> str:
    """A POSIX shell script that re-opens a proven device from its volume-key file.

    LUKS1/2: ``cryptsetup open --type luksN --volume-key-file`` (the on-disk header checks the
    key); plain: ``cryptsetup open --type plain`` with the table's offset/skip/sector size;
    anything else (VeraCrypt: ``--type tcrypt`` needs the header password) replays the exact
    table with ``dmsetup create``.  Every value is shell-quoted.
    """
    import shlex  # stdlib; imported here to keep the module-level import allow-list

    kind = device_type(dm_uuid)
    device = "/dev/" + cfg.disk_name if cfg.disk_name else cfg.dev_name
    lines = [
        "#!/bin/sh",
        "# linux.dmcrypt --export cryptsetup: %s (%s, key %s)" % (_comment_text(name), kind, _comment_text(oracle)),
        "# backing device at capture time: %s (%s); attach the same container and adjust DEVICE."
        % (_comment_text(cfg.dev_name), _comment_text(cfg.disk_name or "?")),
        "set -eu",
        'KEY="$(dirname -- "$0")"/%s' % shlex.quote(key_file),
        "DEVICE=%s" % shlex.quote(device),
    ]
    if kind in ("luks1", "luks2"):
        lines += ["# cryptsetup < 2.4 spells --volume-key-file as --master-key-file",
                  'cryptsetup open --type %s --volume-key-file "$KEY" "$DEVICE" %s' % (kind, shlex.quote(name))]
    elif kind == "plain":
        options = ["--cipher", cfg.cipher_string, "--key-size", str(cfg.key_size * 8), "--hash", "plain",
                   "--keyfile-size", str(cfg.key_size), "--offset", str(cfg.start), "--skip", str(cfg.iv_offset)]
        options += ["--sector-size", str(cfg.sector_size)] if cfg.sector_size != 512 else []
        options += ["--iv-large-sectors"] if iv_large else []
        options += ["--allow-discards"] if discards else []
        lines.append('cryptsetup open --type plain %s --key-file "$KEY" "$DEVICE" %s'
                     % (" ".join(shlex.quote(o) for o in options), shlex.quote(name)))
    else:
        lines += ["# not a cryptsetup LUKS/plain device (VeraCrypt/TrueCrypt: cryptsetup --type tcrypt",
                  "# --veracrypt needs the header password); replay the exact dm table instead.",
                  "# The table names the backing device %s as major:minor; edit it if that changed."
                  % _comment_text(cfg.dev_name),
                  "dmsetup create %s --table %s" % (shlex.quote(name), shlex.quote(replay_line))]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- device-mapper walk


@dataclass
class DmDevice:
    name: str
    uuid: str
    dm_name: str
    table: int
    disk: int = 0  # struct gendisk * of the dm device (O3 reads its plaintext page cache)


def iter_rb_nodes(reader: SafeReader, kl: KernelLayout, root_node: Optional[int]) -> Iterator[int]:
    """In-order rb-tree walk (iterative, cycle- and size-bounded)."""
    return _iter_rb(reader, kl["rb_node.rb_left"], kl["rb_node.rb_right"], root_node, MAX_DEVICES)


def _device_from_md(reader: SafeReader, kl: KernelLayout, md: int,
                    name: Optional[str], uuid: Optional[str]) -> Optional[DmDevice]:
    table = reader.ptr(md + kl["mapped_device.map"])
    disk = reader.ptr(md + kl["mapped_device.disk"])
    dm_name = reader.inline_string(disk + kl["gendisk.disk_name"], 32) if disk else None
    if not table:
        return None
    return DmDevice(name or reader.inline_string(md + kl["mapped_device.name"], 16) or "?",
                    uuid or "", dm_name or "", table, disk or 0)


def iter_devices_rb(reader: SafeReader, kl: KernelLayout, root: int) -> Iterator[DmDevice]:
    for node in iter_rb_nodes(reader, kl, reader.ptr(root)):
        cell = node - kl["hash_cell.name_node"]
        md = reader.ptr(cell + kl["hash_cell.md"])
        if not md:
            continue
        device = _device_from_md(reader, kl, md, reader.cstring(reader.ptr(cell + kl["hash_cell.name"])),
                                 reader.cstring(reader.ptr(cell + kl["hash_cell.uuid"])))
        if device is not None:
            yield device


def iter_crypt_targets(reader: SafeReader, kl: KernelLayout,
                       table: int) -> Iterator[Tuple[int, int, int, int, int]]:
    """``(index, begin, len, private, num_discard_bios)`` of each ``crypt`` target."""
    count = reader.u32(table + kl["dm_table.num_targets"]) or 0
    targets = reader.ptr(table + kl["dm_table.targets"])
    size = kl.sizes.get("dm_target", 80)
    for index in range(min(count, MAX_TARGETS)) if targets else ():
        target = targets + index * size
        ttype = reader.ptr(target + kl["dm_target.type"])
        if not ttype or reader.cstring(reader.ptr(ttype + kl["target_type.name"]), 32) != "crypt":
            continue
        yield (index, reader.u64(target + kl["dm_target.begin"]) or 0,
               reader.u64(target + kl["dm_target.len"]) or 0,
               reader.ptr(target + kl["dm_target.private"]) or 0,
               reader.u32(target + kl["dm_target.num_discard_bios"]) or 0)


# --------------------------------------------------------------------------- the plugin


class DmCrypt(interfaces.plugins.PluginInterface):
    """Lists active dm-crypt devices and recovers each volume key, proven from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.StringRequirement(
                name="offsets", optional=True,
                description="JSON with crypt_config (and optional dm_core) member offsets"),
            requirements.ChoiceRequirement(
                name="export", choices=["masterkey", "dmsetup", "json", "cryptsetup"], optional=True,
                description="Write raw key files (proven keys only), dmsetup lines, a JSON report or "
                            "cryptsetup/dmsetup open scripts with key files (proven keys only)"),
            requirements.BooleanRequirement(
                name="export_unverified", optional=True, default=False,
                description="With --export masterkey also write keys that are not proven"),
            requirements.BooleanRequirement(
                name="verbose", optional=True, default=False,
                description="Add status, driver and proof-detail columns"),
            btf_layouts.btf_method_requirement(),
        ]

    # ------------------------------------------------------------------ setup

    def _setup(self) -> None:
        self.vmlinux, self.layer, self.reader = kernel_reader(self.context, self.config["kernel"])
        self.byteorder = self.reader.byteorder
        self.arch = arch_of(self.layer)
        self.kver = kernel_release(self.vmlinux, self.reader)

    def _setup_layout(self) -> None:
        dm_core = self.offsets.dm_core if self.offsets is not None else {}
        self.kl = KernelLayout.from_module(self.vmlinux, dm_core,
                                           getattr(self, "dm_core_source", "table"))
        defaulted = self.kl.defaulted()
        if defaulted:
            vollog.warning("ISF/offset table lack %d offsets, guessed from the LP64 6.8 layout: %s",
                           len(defaulted), ", ".join(defaulted))
        if self.kl.key_path_defaulted():
            vollog.warning("guessed offsets on the key path (%s): no key will be labelled proven",
                           ", ".join(self.kl.key_path_defaulted()))

    def _load_offsets(self) -> Optional[dm_offsets.DmCryptOffsets]:
        """``--offsets``, else trusted memory BTF > table entry; raises ``ValueError``/``OSError``.

        dm core offsets are filled independently (``_fill_dm_core``) when the chosen offsets lack
        them and the ISF does too.
        """
        self.dm_core_source = "table"
        path = self.config.get("offsets")
        if path:
            with open(path, "r", encoding="utf-8") as handle:
                chosen = dm_offsets.load_offsets_json(handle.read(), "--offsets " + path, self.kver)
            return self._fill_dm_core(chosen, None)
        table = dm_offsets.lookup_offsets(self.arch, self.kver)
        memory = self._memory_offsets()
        if memory is None:
            return self._fill_dm_core(table, None)
        differ = dm_offsets.differences(memory, table)
        if differ:
            vollog.warning("in-memory dm_crypt BTF differs from the built-in table for %s %s (%d; using "
                           "memory): %s", self.arch, self.kver, len(differ), "; ".join(differ))
        return self._fill_dm_core(memory, table)

    def _fill_dm_core(self, chosen: Optional[dm_offsets.DmCryptOffsets],
                      table: Optional[dm_offsets.DmCryptOffsets]) -> Optional[dm_offsets.DmCryptOffsets]:
        """Give ``chosen`` dm core offsets when it has none: trusted dm_mod BTF, else the table's."""
        if chosen is None or chosen.dm_core:
            return chosen
        dm_core = self._memory_dm_core(getattr(self, "context", None), self.config.get("btf_method"))
        if dm_core:
            self.dm_core_source = "btf-memory"
            return replace(chosen, dm_core=dm_core)
        if table is not None and table.dm_core:
            return replace(chosen, dm_core=dict(table.dm_core))
        return chosen

    def _memory_offsets(self) -> Optional[dm_offsets.DmCryptOffsets]:
        """crypt_config + ``enum flags`` / ``enum cipher_flags`` from the image's dm_crypt BTF."""
        recovered = btf_layouts.recover_trusted(getattr(self, "context", None), self.config.get("kernel"),
                                                "dm_crypt", ("crypt_config",), self.config.get("btf_method"))
        if recovered is None or recovered.btf is None:
            return None
        crypt_config = {m.name: m.offset for m in recovered.structs["crypt_config"].members
                        if not m.bitfield_size and not m.bit_offset % 8}
        try:
            flags = _named_enum(recovered.btf, "flags", "DM_CRYPT_")
            cipher_flags = _named_enum(recovered.btf, "cipher_flags", "CRYPT_")
        except btf_memory.BtfParseError as error:
            vollog.info("btf-memory dm_crypt: %s: not used", error)
            return None
        offsets = dm_offsets.from_memory(crypt_config, flags, cipher_flags, recovered.source)
        if offsets is None:
            vollog.info("btf-memory dm_crypt: required members or flag enumerators missing/out of "
                        "range: not used")
        return offsets

    def _memory_dm_core(self, context: Any, method: Optional[str]) -> Dict[str, int]:
        """dm core offsets from the ``dm_mod`` module BTF, only when the ISF lacks the dm structs."""
        try:
            self.vmlinux.get_type("hash_cell")
            return {}  # dm core is built in: the ISF describes it
        except (exceptions.SymbolError, AttributeError):
            pass
        recovered = btf_layouts.recover_trusted(context, self.config.get("kernel"), "dm_mod",
                                                DM_MOD_STRUCTS, method)
        return dm_core_from_layouts(recovered.structs) if recovered is not None else {}

    # ------------------------------------------------------------------ walk roots

    def _walk_roots(self) -> Tuple[Optional[int], Optional[int], str]:
        """``(name_rb_tree, _minor_idr, origin)`` from vmlinux, else from ``dm_mod``'s kallsyms."""
        rb_root, idr = symbol_address(self.vmlinux, "name_rb_tree"), symbol_address(self.vmlinux, "_minor_idr")
        if rb_root or idr:
            return rb_root, idr, "vmlinux"
        module = find_module(self.vmlinux, "dm_mod")  # dm core built as a module
        if module is None:
            return None, None, "neither vmlinux nor a loaded dm_mod module has the dm symbols"
        rb_root, idr = module_symbol(module, "name_rb_tree"), module_symbol(module, "_minor_idr")
        found = [n for n, a in (("name_rb_tree", rb_root), ("_minor_idr", idr)) if a]
        return rb_root, idr, "module dm_mod (kallsyms: %s)" % (", ".join(found) or "no dm roots")

    def _devices(self) -> List[DmDevice]:
        rb_root, idr, origin = self._walk_roots()
        if not rb_root and not idr:
            vollog.warning("device-mapper walk impossible: %s (dm-crypt needs dm_mod; if it is "
                           "loaded, its kallsyms were unreadable)", origin)
            return []
        if self.kl.missing_walk():
            vollog.warning(
                "dm core roots found in %s, but the vmlinux ISF lacks the dm structs (%s) -- dm_mod "
                "is a loadable module on this kernel. Pass --offsets with a \"dm_core\" section "
                "(pahole/BTF of dm_mod, keys \"type.member\") to walk it.",
                origin, ", ".join(self.kl.missing_walk()))
            return []
        vollog.info("dm walk roots from %s", origin)
        devices = list(iter_devices_rb(self.reader, self.kl, rb_root)) if rb_root else []
        return devices or self._devices_from_idr(idr)

    def _devices_from_idr(self, idr_address: Optional[int]) -> List[DmDevice]:
        """Fallback: ``_minor_idr`` -> mapped_device -> ``interface_ptr`` (the hash_cell)."""
        if not idr_address:
            return []
        try:
            idr = self.context.object(self.vmlinux.symbol_table_name + constants.BANG + "idr",
                                      layer_name=self.vmlinux.layer_name, offset=idr_address)
            pointers = list(idr.get_entries())
        except (exceptions.SymbolError, AttributeError, exceptions.InvalidAddressException, ValueError):
            return []
        devices = []
        for md in pointers:
            md = int(md)
            cell = self.reader.ptr(md + self.kl["mapped_device.interface_ptr"]) if md > 1 else None
            name = self.reader.cstring(self.reader.ptr(cell + self.kl["hash_cell.name"])) if cell else None
            uuid = self.reader.cstring(self.reader.ptr(cell + self.kl["hash_cell.uuid"])) if cell else None
            device = _device_from_md(self.reader, self.kl, md, name, uuid)
            if device is not None:
                devices.append(device)
        return devices

    # ------------------------------------------------------------------ records

    def _records(self) -> List[Dict[str, Any]]:
        records = []
        devices = self._devices()
        for device in devices:
            for index, begin, length, private, discards in iter_crypt_targets(
                    self.reader, self.kl, device.table):
                records.append(self._record(device, index, begin, length, private, discards))
        vollog.info("%d dm devices walked", len(devices))
        return records

    def _record(self, device: DmDevice, index: int, begin: int, length: int,
                private: int, discards: int) -> Dict[str, Any]:
        record: Dict[str, Any] = {"device": device, "index": index, "begin": begin,
                                  "length": length, "private": private, "cfg": None, "discards": discards,
                                  "recovery": None, "probe": None}
        if self.offsets is None:
            record["probe"] = probe_crypt_basics(self.reader, self.kl, private)
            record["why"] = "no crypt_config offsets for %s %s: pass --offsets" % (self.arch, self.kver)
            return record
        cfg, why = relocate_crypt_config(self.reader, self.kl, private, self.offsets)
        record["why"] = why
        if cfg is None:
            vollog.warning("%s: crypt_config @%#x rejected: %s", device.name, private, why)
            record["probe"] = probe_crypt_basics(self.reader, self.kl, private)
            return record
        record["cfg"] = cfg
        record["recovery"] = recover_key(self.reader, self.kl, cfg, self.byteorder)
        record["line"] = lambda key_hex: dmsetup_line(begin, length, cfg, key_hex, discards, self.offsets)
        record["replay_line"] = lambda key_hex: dmsetup_line(begin, length, replace(cfg, key_string=None),
                                                             key_hex, discards, self.offsets)
        return record

    # ------------------------------------------------------------------ O2 + verdicts

    def _physical_layer(self) -> Any:
        name = self.layer.config.get("memory_layer")
        return self.context.layers[name] if name in self.context.layers else self.layer

    def _luks_index(self, records: List[Dict[str, Any]]) -> Optional[LuksIndex]:
        wanted = sorted({luks_uuid_from_dm(r["device"].uuid) for r in records
                         if r["recovery"] and r["recovery"].key and luks_uuid_from_dm(r["device"].uuid)})
        if not wanted:
            return None
        physical = self._physical_layer()
        reader = SafeReader(physical, self.reader.pointer_size, self.byteorder)
        scanner = scanners.MultiStringScanner(list(LUKS_SCAN_NEEDLES))
        hits = [(int(a), bytes(n)) for a, n in physical.scan(
            self.context, scanner, progress_callback=self._progress_callback)]
        index = build_luks_index(reader.read, hits, wanted)
        vollog.info("O2: %d LUKS headers resident for %d/%d wanted UUIDs",
                    sum(map(len, index.headers.values())), len(index.headers), len(wanted))
        return index

    def _apply_verdicts(self, records: List[Dict[str, Any]]) -> None:
        index = self._luks_index(records)
        guard = self.kl.key_path_defaulted()
        o3_setup = self._o3_setup() if any(r["recovery"] and r["recovery"].key for r in records) else None
        for record in records:
            uuid = record["device"].uuid
            o2 = (lambda key, uuid=uuid: prove_o2(index, uuid, key)) if index is not None else None
            o3 = self._o3_prover(record, *o3_setup) if o3_setup and record["recovery"] and \
                record["recovery"].key else None
            record["verdict"] = decide(record["recovery"], o2, guard, o3)
            if o3 is not None:
                vollog.info("O3 %s: %s: %s (%d page reads, %d units, %.3f s)", record["device"].name,
                            record["verdict"].o3[0], record["verdict"].o3[1], o3.reads, o3.units, o3.seconds)

    # ------------------------------------------------------------------ O3

    def _o3_layout(self) -> Dict[str, int]:
        layout = o3_layout(lambda type_name, member: isf_offset(self.vmlinux, type_name, member),
                           lambda type_name: isf_size(self.vmlinux, type_name))
        if "dm_dev.bdev" not in self.kl.defaulted():
            layout["dm_dev.bdev"] = self.kl["dm_dev.bdev"]
        return layout

    def _o3_loop_layout(self, layout: Dict[str, int]) -> bool:
        """``loop_device`` from the ``loop`` module's trusted BTF (loop built as a module); once."""
        if getattr(self, "_o3_loop_tried", False):
            return False
        self._o3_loop_tried = True
        recovered = btf_layouts.recover_trusted(getattr(self, "context", None), self.config.get("kernel"),
                                                "loop", ("loop_device",), self.config.get("btf_method"))
        struct_ = recovered.structs.get("loop_device") if recovered is not None else None
        for key in O3_LOOP_MEMBERS + (O3_LOOP_CHECK,):
            found = struct_.member(key.split(".", 1)[1]) if struct_ is not None else None
            if found is not None and not found.bitfield_size:
                layout[key] = found.offset
        return all(k in layout for k in O3_LOOP_MEMBERS)

    def _o3_pages(self, layout: Dict[str, int]) -> O3Pages:
        vmemmap = symbol_address(self.vmlinux, "vmemmap_base")
        to_phys = pagecache.make_page_to_phys(
            self.reader.ptr(vmemmap) if vmemmap else None, layout["sizeof(page)"],
            lambda address: self.vmlinux.object("page", offset=address, absolute=True))
        physical = SafeReader(self._physical_layer(), self.reader.pointer_size, self.byteorder)
        return O3Pages(
            lambda mapping, index: pagecache.mapping_page(self.reader, layout, mapping, index, to_phys),
            lambda mapping, limit: pagecache.iter_mapping_pages(self.reader, layout, mapping, limit, to_phys),
            lambda phys: physical.read(phys, PAGE))

    def _o3_setup(self) -> Tuple[Dict[str, int], Optional[O3Pages], str]:
        """``(layout, pages, why)``: ``why`` is the ``n/a`` reason when O3 cannot run at all."""
        layout = self._o3_layout()
        missing = o3_missing(layout)
        if missing:
            vollog.info("O3 n/a: the ISF lacks %s", ", ".join(missing))
            return layout, None, "layout: " + ", ".join(missing)
        return layout, self._o3_pages(layout), ""

    def _o3_prover(self, record: Dict[str, Any], layout: Dict[str, int], pages: Optional[O3Pages],
                   why: str) -> O3Prover:
        cfg = record["cfg"]
        if pages is None:
            return O3Prover(O3Pages(lambda m, i: None, lambda m, n: iter(()), lambda p: None), cfg,
                            record["begin"], record["length"], False, None, None, why)
        cipher, why = ciphertext_source(self.reader, layout, cfg)
        if why.startswith("layout: loop_device") and self._o3_loop_layout(layout):
            cipher, why = ciphertext_source(self.reader, layout, cfg)
        iv_large = _bit(cfg.cipher_flags, self.offsets.cipher_flag_bits, "CRYPT_IV_LARGE_SECTORS")
        return O3Prover(pages, cfg, record["begin"], record["length"], iv_large, cipher,
                        plaintext_source(self.reader, layout, record["device"]), why)

    # ------------------------------------------------------------------ output

    @staticmethod
    def oracle_label(recovery: Optional[Recovery], o2: Tuple[str, str, Optional[int]],
                     o3: Tuple[str, str, str] = O3_NA) -> str:
        """Label for a recovery with precomputed O2 / O3 results (the same for every key)."""
        return decide(recovery, (lambda key: o2) if o2[0] != "n/a" else None, (),
                      (lambda key: o3) if o3[0] != "n/a" else None).oracle

    def _row(self, record: Dict[str, Any]) -> Tuple:
        na = renderers.NotApplicableValue()
        device, cfg, verdict = record["device"], record["cfg"], record["verdict"]
        probe = record.get("probe") or {}
        key = verdict.key
        row = [
            device.name, device.uuid or na, device.dm_name or na,
            "crypt:%d+%d" % (record["begin"], record["length"]),
            cfg.cipher_string if cfg else (probe.get("cipher") or na),
            (cfg.spec.ivmode + (":" + cfg.spec.ivopts if cfg.spec.ivopts else "")
             if cfg and cfg.spec.ivmode else na),
            cfg.sector_size if cfg else na,
            "%s (%s)" % (cfg.dev_name, cfg.disk_name) if cfg else (probe.get("device") or na),
            cfg.key_size if cfg else na,
            key.hex() if key else na,
            verdict.source if key else na,
            verdict.oracle,
            format_hints.Hex(record["private"]),
        ]
        if self.config.get("verbose"):
            o2, o3 = verdict.o2, verdict.o3
            row += [verdict.status, ", ".join(cfg.tfm_names) if cfg else na,
                    record["recovery"].detail if record["recovery"] else record["why"],
                    "%s: %s" % (o2[0], o2[1]) if o2[1] else o2[0],
                    "%s: %s" % (o3[0], o3[1]) if o3[1] else o3[0]]
        return tuple(row)

    def _columns(self) -> List[Tuple[str, Any]]:
        columns = [("Name", str), ("UUID", str), ("DM", str), ("Target", str), ("Cipher", str),
                   ("IV", str), ("SectorSize", int), ("Device", str), ("KeySize", int),
                   ("Key", str), ("Source", str), ("Oracle", str),
                   ("Offset(V)", format_hints.Hex)]
        if self.config.get("verbose"):
            columns += [("Status", str), ("Driver", str), ("Detail", str), ("O2", str), ("O3", str)]
        return columns

    def _export(self, records: List[Dict[str, Any]]) -> None:
        mode = self.config.get("export")
        if mode == "masterkey":
            self._export_masterkeys(records)
        elif mode == "dmsetup":
            lines = ["%s: %s" % (r["device"].name, r["line"](
                r["verdict"].key.hex() if r["verdict"].key else None)) for r in records if r["cfg"]]
            with self.open("dmcrypt.dmsetup.txt") as handle:
                handle.write(("\n".join(lines) + "\n").encode("ascii"))
        elif mode == "json":
            with self.open("dmcrypt.json") as handle:
                handle.write(json.dumps(self._json_report(records), indent=1).encode("utf-8"))
        elif mode == "cryptsetup":
            self._export_cryptsetup(records)

    def _export_cryptsetup(self, records: List[Dict[str, Any]]) -> None:
        """Per proven target: ``dmcrypt.<name>.volume-key`` (raw) + ``dmcrypt.<name>.open.sh``."""
        for record in records:
            verdict, cfg, device = record["verdict"], record["cfg"], record["device"]
            if not verdict.key or cfg is None or verdict.status != PROVEN:
                vollog.warning("%s: key is %s (%s), no cryptsetup script written", device.name,
                               verdict.status, verdict.oracle)
                continue
            stem = "dmcrypt.%s%s" % (device.name, ".t%d" % record["index"] if record["index"] else "")
            with self.open(stem + ".volume-key") as handle:
                handle.write(verdict.key)
            iv_large = _bit(cfg.cipher_flags, self.offsets.cipher_flag_bits, "CRYPT_IV_LARGE_SECTORS")
            script = cryptsetup_script(device.name, device.uuid, cfg, stem + ".volume-key",
                                       record["replay_line"](verdict.key.hex()), verdict.oracle,
                                       bool(record.get("discards")), iv_large)
            with self.open(stem + ".open.sh") as handle:
                handle.write(script.encode("utf-8"))

    def _export_masterkeys(self, records: List[Dict[str, Any]]) -> None:
        unverified = self.config.get("export_unverified")
        for record in records:
            verdict = record["verdict"]
            if not verdict.key:
                continue
            if verdict.status != PROVEN and not unverified:
                vollog.warning("%s: key is %s (%s), not written; --export-unverified writes it",
                               record["device"].name, verdict.status, verdict.oracle)
                continue
            with self.open("dmcrypt.%s.masterkey" % record["device"].name) as handle:
                handle.write(verdict.key)

    def _json_report(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        report = []
        for record in records:
            cfg, verdict = record["cfg"], record["verdict"]
            key = verdict.key
            report.append({
                "name": record["device"].name, "uuid": record["device"].uuid,
                "dm": record["device"].dm_name, "crypt_config": record["private"],
                "cipher": cfg.cipher_string if cfg else (record.get("probe") or {}).get("cipher"),
                "key_hex": key.hex() if key else None, "status": verdict.status,
                "source": verdict.source if key else None, "oracle": verdict.oracle,
                "o2": {"verdict": verdict.o2[0], "detail": verdict.o2[1]},
                "o3": {"verdict": verdict.o3[0], "detail": verdict.o3[1], "evidence": verdict.o3[2]},
                "dmsetup": record["line"](key.hex() if key else None) if cfg else None,
                "detail": record["recovery"].detail if record["recovery"] else record["why"],
            })
        return report

    def _generator(self, records: List[Dict[str, Any]]) -> Iterator[Tuple[int, Tuple]]:
        for record in records:
            yield 0, self._row(record)

    def _collect(self) -> List[Dict[str, Any]]:
        try:
            self.offsets = self._load_offsets()
        except (OSError, ValueError) as error:
            vollog.error("--offsets %s unusable: %s", self.config.get("offsets"), error)
            return []
        if self.offsets is None:
            vollog.warning("no crypt_config offsets for %s %s: targets are listed without keys; "
                           "pass --offsets (pahole/BTF of dm_crypt)", self.arch, self.kver)
        else:
            vollog.info("crypt_config offsets: %s", self.offsets.source)
        self._setup_layout()
        records = self._records()
        self._apply_verdicts(records)
        return records

    def run(self) -> renderers.TreeGrid:
        self._setup()
        self.kl = KernelLayout()
        records = self._collect()
        statuses = [r["verdict"].status for r in records]
        vollog.info("linux.dmcrypt: %d crypt targets, %d keys, %d proven, %d not proven (%s %s)",
                    len(records), sum(1 for r in records if r["verdict"].key),
                    statuses.count(PROVEN), len(statuses) - statuses.count(PROVEN),
                    self.arch, self.kver)
        if self.config.get("export"):
            self._export(records)
        return renderers.TreeGrid(self._columns(), self._generator(records))
