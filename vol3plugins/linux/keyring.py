"""``linux.keyring`` -- the kernel key serial tree, every key's payload decoded and labelled.

Walk
----
``key_serial_tree`` (``security/keys/key.c``; an ``rb_root`` ordered by serial) ->
``key.serial_node`` -> ``struct key``.  Every offset comes from the vmlinux ISF (the keys
subsystem is built in); members inside the anonymous unions of ``struct key`` are found by a
bounded recursive member search.  An LP64 6.8 table is only the fallback and is announced.
The walk is iterative and bounded (``MAX_KEYS``) and stops on any node it has already seen, so
a corrupted or cyclic tree cannot loop.

Payloads (``key.payload.data[0]``)
----------------------------------
* ``user`` / ``logon`` -> ``struct user_key_payload {rcu; u16 datalen; char data[]}``
  (``security/keys/user_defined.c``); ``datalen`` must equal ``key.datalen``.
* ``encrypted`` -> ``struct encrypted_key_payload``: the *decrypted* key
  (``decrypted_data``/``decrypted_datalen``) plus ``format`` and ``master_desc``.
* ``fscrypt-provisioning`` -> ``struct fscrypt_provisioning_key_payload {type; raw[]}``.
* ``trusted`` -> flagged only (TPM-sealed; not decoded).
* ``keyring`` -> member count (``keys.nr_leaves_on_tree``).
* ``asymmetric`` -> ``id_type.pkey_algo`` and the key id tail, as ``/proc/keys`` prints it.

Semantics and proof (``Status`` is ``proven`` only when an oracle passed)
--------------------------------------------------------------------------
* ``logon``/``user cryptsetup:<uuid>-d<n>`` (cryptsetup's LUKS2 kernel-keyring volume key,
  ``lib/utils_keyring.c``/``lib/luks2/luks2_digest.c``; ``logon`` for the internal dm-crypt
  hand-over, ``user`` -- the ``--link-vk-to-keyring`` default type -- when the volume key is
  linked into a user keyring) -> ``dmcrypt-volume-key``; **proven**
  (``dmcrypt-cross``) when the payload is byte-equal to the key ``linux.dmcrypt`` proves for the
  dm device whose ``CRYPT-LUKS2-<uuid>-`` matches.
* ``user`` payload of ``sizeof(struct ecryptfs_auth_tok)`` with a password token ->
  ``ecryptfs-auth_tok``: FEKEK = ``token.password.session_key_encryption_key``; **proven**
  (``ecryptfs-sig``) when ``signature == hex(SHA-512(FEKEK)[:8])`` -- ecryptfs-utils
  ``generate_passphrase_sig()`` (src/libecryptfs/key_management.c) hashes the 64-byte FEKEK
  with SHA-512 and hex-encodes ``ECRYPTFS_SIG_SIZE`` (8) bytes.
* ``logon fscrypt:<16 hex>`` (also ``ext4:``/``f2fs:``/``ubifs:``) -> ``struct fscrypt_key``
  (v1 master key, ``Documentation/filesystems/fscrypt.rst`` "Adding keys" / legacy keyring);
  **proven** (``fscrypt-desc``) when the descriptor equals ``SHA-512(SHA-512(raw))[:8]`` --
  the descriptor fscryptctl (``compute_descriptor``) and fscrypt (``crypto.ComputeKeyDescriptor``,
  v1 policies) derive.  The kernel does not enforce it, so a mismatch stays ``decoded``.
  fscrypt v1/v2 keys added with ``FS_IOC_ADD_ENCRYPTION_KEY`` live in the superblock's
  ``fscrypt_keyring`` (not ``struct key``); only the v2 per-user claim (``.fscrypt``) shows here.
"""

import datetime
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import dmcrypt
from .kernel_common import (IsfLayout, SafeReader, arch_of, find_member, isf_offset, isf_size, iter_rb_nodes,
                            kernel_reader, symbol_address)

vollog = logging.getLogger(__name__)

MAX_KEYS = 1 << 17
MAX_PAYLOAD = 0xFFFF  # key.datalen is a u16
PREVIEW_BYTES = 32
OVERFLOW_ID = 65534  # from_k[ug]id_munged() of an unmapped id
INVALID_ID = 0xFFFFFFFF
PAGE = 4096
TIME64_MAX = (1 << 63) - 1  # key->expiry of a key that never expires (security/keys/key.c)

PROVEN, DECODED, UNVERIFIED, TRUNCATED, UNREADABLE, NA = (
    "proven", "decoded", "unverified", "truncated", "unreadable", "n/a")

# include/linux/key.h (v6.8) KEY_FLAG_* bit numbers.
KEY_FLAGS = ("DEAD", "REVOKED", "IN_QUOTA", "USER_CONSTRUCT", "ROOT_CAN_CLEAR",
             "INVALIDATED", "BUILTIN", "ROOT_CAN_INVAL", "KEEP", "UID_KEYRING")
ECRYPTFS_PASSWORD = 0  # include/linux/ecryptfs.h token_type
FSCRYPT_MAX_KEY_SIZE = 64
DMCRYPT_DESC_RE = re.compile(r"^cryptsetup:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                             r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})-d([0-9]+)$")
FSCRYPT_DESC_RE = re.compile(r"^(fscrypt|ext4|f2fs|ubifs):([0-9a-f]{16})$")
FSCRYPT_CLAIM_RE = re.compile(r"^([0-9a-f]{32})\.uid\.([0-9]+)$")


# --------------------------------------------------------------------------- layout

# "name" -> (type, member) resolved through anonymous unions; value = LP64 6.8 fallback.
_FIELDS = {
    "key.usage": ("key", "usage", 0), "key.serial": ("key", "serial", 4),
    "key.serial_node": ("key", "serial_node", 8), "key.expiry": ("key", "expiry", 96),
    "key.last_used_at": ("key", "last_used_at", 104), "key.uid": ("key", "uid", 112),
    "key.gid": ("key", "gid", 116), "key.perm": ("key", "perm", 120),
    "key.datalen": ("key", "datalen", 126), "key.state": ("key", "state", 128),
    "key.flags": ("key", "flags", 136), "key.type": ("key", "type", 160),
    "key.description": ("key", "description", 176), "key.payload": ("key", "payload", 184),
    "key.keys": ("key", "keys", 200),
    "rb_node.rb_right": ("rb_node", "rb_right", 8), "rb_node.rb_left": ("rb_node", "rb_left", 16),
    "key_type.name": ("key_type", "name", 0),
    "assoc_array.nr_leaves_on_tree": ("assoc_array", "nr_leaves_on_tree", 8),
    "user_key_payload.datalen": ("user_key_payload", "datalen", 16),
    "user_key_payload.data": ("user_key_payload", "data", 24),
    "ecryptfs_auth_tok.version": ("ecryptfs_auth_tok", "version", 0),
    "ecryptfs_auth_tok.token_type": ("ecryptfs_auth_tok", "token_type", 2),
    "ecryptfs_auth_tok.token": ("ecryptfs_auth_tok", "token", 628),
    "ecryptfs_password.key_bytes": ("ecryptfs_password", "session_key_encryption_key_bytes", 12),
    "ecryptfs_password.fekek": ("ecryptfs_password", "session_key_encryption_key", 20),
    "ecryptfs_password.signature": ("ecryptfs_password", "signature", 84),
    "fscrypt_key.mode": ("fscrypt_key", "mode", 0), "fscrypt_key.raw": ("fscrypt_key", "raw", 4),
    "fscrypt_key.size": ("fscrypt_key", "size", 68),
    "encrypted_key_payload.format": ("encrypted_key_payload", "format", 16),
    "encrypted_key_payload.master_desc": ("encrypted_key_payload", "master_desc", 24),
    "encrypted_key_payload.decrypted_datalen": ("encrypted_key_payload", "decrypted_datalen", 58),
    "encrypted_key_payload.decrypted_data": ("encrypted_key_payload", "decrypted_data", 64),
    "fscrypt_provisioning_key_payload.type": ("fscrypt_provisioning_key_payload", "type", 0),
    "fscrypt_provisioning_key_payload.raw": ("fscrypt_provisioning_key_payload", "raw", 8),
    "public_key.id_type": ("public_key", "id_type", 32),
    "public_key.pkey_algo": ("public_key", "pkey_algo", 40),
    "asymmetric_key_id.len": ("asymmetric_key_id", "len", 0),
    "asymmetric_key_id.data": ("asymmetric_key_id", "data", 2),
    "cred.session_keyring": ("cred", "session_keyring", 96),
    "cred.process_keyring": ("cred", "process_keyring", 104),
    "cred.thread_keyring": ("cred", "thread_keyring", 112),
}
_SIZES = {"ecryptfs_auth_tok": 740, "fscrypt_key": 72, "ecryptfs_password.signature": 17}
WALK_KEYS = ("key.serial", "key.serial_node", "key.type", "key.description", "key.payload",
             "rb_node.rb_right", "rb_node.rb_left", "key_type.name")


@dataclass
class KeyLayout(IsfLayout):
    """Struct offsets (``"type.member" -> offset``); ``sources`` says isf or default."""

    offsets: Dict[str, int] = field(default_factory=lambda: {k: v[2] for k, v in _FIELDS.items()})
    sizes: Dict[str, int] = field(default_factory=lambda: dict(_SIZES))

    @classmethod
    def from_module(cls, module: Any) -> "KeyLayout":
        layout = cls()
        layout.resolve(lambda key: isf_offset(module, *_FIELDS[key][:2]))
        for key in ("ecryptfs_auth_tok", "fscrypt_key"):
            size = isf_size(module, key)
            if size is not None:
                layout.sizes[key] = size
        return layout


# --------------------------------------------------------------------------- walk


def iter_key_nodes(reader: SafeReader, kl: KeyLayout, root_node: Optional[int],
                   limit: int = MAX_KEYS) -> Iterator[int]:
    """In-order (= ascending serial) rb-tree walk: iterative, cycle-safe, size-bounded."""
    return iter_rb_nodes(reader, kl["rb_node.rb_left"], kl["rb_node.rb_right"], root_node, limit)


def read_prefix(reader: SafeReader, address: int, length: int) -> bytes:
    """Up to ``length`` bytes at ``address``, stopping at the first unreadable page."""
    whole = reader.read(address, length)
    if whole is not None:
        return whole
    out = bytearray()
    cursor = address
    while len(out) < length:
        chunk = min(length - len(out), PAGE - (cursor % PAGE))
        data = reader.read(cursor, chunk)
        if data is None:
            break
        out += data
        cursor += chunk
    return bytes(out)


def read_cstring(reader: SafeReader, address: Optional[int], limit: int = 256) -> Optional[bytes]:
    """Raw bytes of a NUL-terminated string (page-wise, so one ending just before an
    unreadable page still reads); None without a terminator inside ``limit``."""
    data = read_prefix(reader, address, limit) if address else b""
    if b"\0" not in data:
        return None
    return data.split(b"\0", 1)[0]


def _text(raw: Optional[bytes]) -> str:
    """Display form of kernel string bytes (UTF-8, undecodable bytes replaced)."""
    return raw.decode("utf-8", "replace") if raw else ""


def _ascii(record: "KeyRecord") -> str:
    """The description for label/proof matching: strict ASCII from the raw bytes, else ''."""
    try:
        return record.description_raw.decode("ascii")
    except UnicodeDecodeError:
        return ""


def _signed16(value: Optional[int]) -> int:
    value = value or 0
    return value - 0x10000 if value & 0x8000 else value


@dataclass
class KeyRecord:
    address: int
    serial: int
    usage: int
    type_name: str
    description: str
    uid: int
    gid: int
    perm: int
    state: int
    flags: int
    datalen: int
    expiry: int
    last_used: int
    payload_ptr: int
    description_raw: bytes = b""  # the exact kernel bytes; label/proof matching uses these
    payload: Optional[bytes] = None
    semantics: str = ""
    status: str = NA
    secret: Optional[bytes] = None  # the decoded secret (FEKEK, volume key, ...) when it differs
    describe: str = ""
    detail: str = ""
    holders: List[str] = field(default_factory=list)


def read_key(reader: SafeReader, kl: KeyLayout, key: int) -> Optional[KeyRecord]:
    serial = reader.u32(key + kl["key.serial"])
    ktype = reader.ptr(key + kl["key.type"])
    if serial is None or not ktype:
        return None
    type_name = _text(read_cstring(reader, reader.ptr(ktype + kl["key_type.name"]), 64)) or "?"
    description_raw = read_cstring(reader, reader.ptr(key + kl["key.description"]), 4096) or b""
    return KeyRecord(
        address=key, serial=serial, usage=reader.u32(key + kl["key.usage"]) or 0,
        type_name=type_name, description=_text(description_raw), description_raw=description_raw,
        uid=_u32(reader, key + kl["key.uid"]), gid=_u32(reader, key + kl["key.gid"]),
        perm=reader.u32(key + kl["key.perm"]) or 0,
        state=_signed16(reader.u16(key + kl["key.state"])),
        flags=reader.u64(key + kl["key.flags"]) or 0, datalen=reader.u16(key + kl["key.datalen"]) or 0,
        expiry=_expiry(reader.u64(key + kl["key.expiry"])),
        last_used=reader.u64(key + kl["key.last_used_at"]) or 0,
        payload_ptr=reader.ptr(key + kl["key.payload"]) or 0)


def _expiry(value: Optional[int]) -> int:
    """0 = permanent (TIME64_MAX in the kernel); else expiry (or revoked_at when REVOKED)."""
    return 0 if not value or value == TIME64_MAX else value


def _u32(reader: SafeReader, address: int) -> int:
    value = reader.u32(address)
    return INVALID_ID if value is None else value


def iter_keys(reader: SafeReader, kl: KeyLayout, root: int) -> Iterator[KeyRecord]:
    for node in iter_key_nodes(reader, kl, reader.ptr(root)):
        record = read_key(reader, kl, node - kl["key.serial_node"])
        if record is not None:
            yield record


# --------------------------------------------------------------------------- decoders


def _flag(record: KeyRecord, name: str) -> bool:
    return bool(record.flags >> KEY_FLAGS.index(name) & 1)


def decode_user_payload(reader: SafeReader, kl: KeyLayout, record: KeyRecord) -> None:
    """``user``/``logon``: ``user_key_payload.data[datalen]`` (status truncated/unreadable)."""
    if not record.payload_ptr or record.state != 1:
        record.status, record.detail = UNREADABLE, "no payload (state %d)" % record.state
        return
    inner = reader.u16(record.payload_ptr + kl["user_key_payload.datalen"])
    if inner is None:
        record.status, record.detail = UNREADABLE, "user_key_payload unreadable"
        return
    if inner != record.datalen:
        record.detail = "user_key_payload.datalen %d != key.datalen %d" % (inner, record.datalen)
    length = min(inner, MAX_PAYLOAD)
    record.payload = read_prefix(reader, record.payload_ptr + kl["user_key_payload.data"], length)
    if len(record.payload) < length:
        record.status = TRUNCATED
        record.detail = "payload truncated: %d/%d bytes readable" % (len(record.payload), length)
    else:
        record.status = DECODED if inner == record.datalen else UNVERIFIED


def ecryptfs_signature(fekek: bytes) -> str:
    """ecryptfs-utils ``generate_passphrase_sig()``: hex of SHA-512(FEKEK)[:8]."""
    return hashlib.sha512(fekek).hexdigest()[:16]


def fscrypt_v1_descriptor(raw: bytes) -> str:
    """v1 key descriptor: hex of SHA-512(SHA-512(raw))[:8] over the full 64-byte ``raw`` buffer,
    as e4crypt (e2fsprogs misc/e4crypt.c ``generate_key_ref_str``), fscryptctl and fscrypt
    (``crypto.ComputeKeyDescriptor``) derive it."""
    return hashlib.sha512(hashlib.sha512(raw).digest()).hexdigest()[:16]


def decode_ecryptfs(kl: KeyLayout, record: KeyRecord) -> bool:
    """A ``user`` payload that is an ``ecryptfs_auth_tok`` with a password token."""
    data = record.payload or b""
    if len(data) != kl.sizes["ecryptfs_auth_tok"]:
        return False
    token_type = int.from_bytes(data[kl["ecryptfs_auth_tok.token_type"]:][:2], "little")
    pw = kl["ecryptfs_auth_tok.token"]
    nbytes = int.from_bytes(data[pw + kl["ecryptfs_password.key_bytes"]:][:4], "little")
    sig_raw = data[pw + kl["ecryptfs_password.signature"]:][:kl.sizes["ecryptfs_password.signature"]]
    signature = sig_raw.split(b"\0", 1)[0].decode("ascii", "replace")
    if token_type != ECRYPTFS_PASSWORD or not 0 < nbytes <= 64 or not re.match(r"^[0-9a-f]{16}$", signature):
        return False
    fekek = data[pw + kl["ecryptfs_password.fekek"]:][:nbytes]
    record.secret = fekek
    if ecryptfs_signature(fekek) == signature:
        record.status, oracle = PROVEN, "ecryptfs-sig"
    else:
        record.status, oracle = UNVERIFIED, "ecryptfs-sig:mismatch"
    record.semantics = "ecryptfs-auth_tok sig=%s fekek=%dB [%s]" % (signature, nbytes, oracle)
    if signature != _ascii(record):
        record.detail = "auth_tok signature differs from the key description"
    return True


def decode_fscrypt_v1(kl: KeyLayout, record: KeyRecord) -> bool:
    """A ``logon fscrypt:<desc>`` payload: ``struct fscrypt_key {mode, raw[64], size}``."""
    match = FSCRYPT_DESC_RE.match(_ascii(record))
    data = record.payload or b""
    if not match or len(data) != kl.sizes["fscrypt_key"]:
        return False
    size = int.from_bytes(data[kl["fscrypt_key.size"]:][:4], "little")
    mode = int.from_bytes(data[kl["fscrypt_key.mode"]:][:4], "little")
    if not 0 < size <= FSCRYPT_MAX_KEY_SIZE:
        return False
    raw_buffer = data[kl["fscrypt_key.raw"]:][:FSCRYPT_MAX_KEY_SIZE]
    record.secret = raw_buffer[:size]
    proven = fscrypt_v1_descriptor(raw_buffer) == match.group(2)
    record.status = PROVEN if proven else DECODED
    record.semantics = "fscrypt-v1-master desc=%s mode=%d size=%d [%s]" % (
        match.group(2), mode, size, "fscrypt-desc" if proven else "desc-not-derived")
    return True


def is_cryptsetup_volume_key(record: KeyRecord) -> bool:
    """A ``user``/``logon`` key named ``cryptsetup:<uuid>-d<n>`` (cryptsetup's volume-key names)."""
    return record.type_name in ("user", "logon") and bool(DMCRYPT_DESC_RE.match(_ascii(record)))


def decode_dmcrypt(record: KeyRecord, dm_keys: Dict[str, List[Tuple[bytes, str]]]) -> bool:
    """``user``/``logon cryptsetup:<uuid>-d<n>``: the LUKS2 volume key cryptsetup handed dm-crypt."""
    match = DMCRYPT_DESC_RE.match(_ascii(record))
    if not match or not record.payload:
        return False
    uuid, segment = match.group(1).lower(), int(match.group(2))
    candidates = dm_keys.get(uuid.replace("-", ""), [])
    statuses = [status for key, status in candidates if key == record.payload]
    if dmcrypt.PROVEN in statuses:
        record.status, oracle = PROVEN, "dmcrypt-cross"
    elif statuses:
        oracle = "dmcrypt-match:dmcrypt-unproven"
    else:
        oracle = "dmcrypt-mismatch" if candidates else "no-dm-device"
    record.semantics = "dmcrypt-volume-key uuid=%s seg=%d %dbit [%s]" % (
        uuid, segment, len(record.payload) * 8, oracle)
    return True


def decode_encrypted(reader: SafeReader, kl: KeyLayout, record: KeyRecord) -> None:
    payload = record.payload_ptr
    fmt = _text(read_cstring(reader, reader.ptr(payload + kl["encrypted_key_payload.format"]), 32)) if payload else ""
    master = _text(read_cstring(reader, reader.ptr(payload + kl["encrypted_key_payload.master_desc"]))) if payload else ""
    length = reader.u16(payload + kl["encrypted_key_payload.decrypted_datalen"]) if payload else None
    data_ptr = reader.ptr(payload + kl["encrypted_key_payload.decrypted_data"]) if payload else None
    record.semantics = "encrypted format=%s master=%s" % (fmt or "?", master or "?")
    if not length or not data_ptr:
        record.status, record.detail = UNREADABLE, "encrypted_key_payload unreadable"
        return
    record.payload = read_prefix(reader, data_ptr, length)
    record.secret = record.payload
    record.status = DECODED if len(record.payload) == length else TRUNCATED


def decode_provisioning(reader: SafeReader, kl: KeyLayout, record: KeyRecord) -> None:
    payload, header = record.payload_ptr, kl["fscrypt_provisioning_key_payload.raw"]
    spec = reader.u32(payload + kl["fscrypt_provisioning_key_payload.type"]) if payload else None
    length = max(record.datalen - header, 0)
    record.payload = read_prefix(reader, payload + header, length) if payload and length else b""
    record.secret = record.payload
    record.status = DECODED if record.payload and len(record.payload) == length else TRUNCATED
    record.semantics = "fscrypt-provisioning %s" % {1: "v1-descriptor", 2: "v2-identifier"}.get(
        spec or 0, "type=%s" % spec)


def keyring_members(reader: SafeReader, kl: KeyLayout, record: KeyRecord) -> Optional[int]:
    return reader.u64(record.address + kl["key.keys"] + kl["assoc_array.nr_leaves_on_tree"])


def asymmetric_describe(reader: SafeReader, kl: KeyLayout, record: KeyRecord) -> str:
    """``asymmetric_key_describe()``: ``id_type.pkey_algo <last 4 id bytes> []``."""
    pub = record.payload_ptr  # payload.data[asym_crypto] = struct public_key
    if not pub:
        return ""
    id_type = _text(read_cstring(reader, reader.ptr(pub + kl["public_key.id_type"]), 16)) or "?"
    algo = _text(read_cstring(reader, reader.ptr(pub + kl["public_key.pkey_algo"]), 32)) or "?"
    kids = reader.ptr(record.address + kl["key.payload"] + 2 * reader.pointer_size)
    kid = reader.ptr(kids + reader.pointer_size) if kids else None  # id[1]
    tail = ""
    if kid:
        length = reader.u16(kid + kl["asymmetric_key_id.len"]) or 0
        data = reader.read(kid + kl["asymmetric_key_id.data"] + max(length - 4, 0), min(length, 4))
        tail = data.hex() if data else ""
    return "%s.%s %s []" % (id_type, algo, tail)


# --------------------------------------------------------------------------- /proc/keys


def proc_flags(record: KeyRecord) -> str:
    """The 7-character flag column of ``proc_keys_show()`` (security/keys/proc.c)."""
    return "".join((
        "I" if record.state != 0 else "-", "R" if _flag(record, "REVOKED") else "-",
        "D" if _flag(record, "DEAD") else "-", "Q" if _flag(record, "IN_QUOTA") else "-",
        "U" if _flag(record, "USER_CONSTRUCT") else "-", "N" if record.state < 0 else "-",
        "i" if _flag(record, "INVALIDATED") else "-"))


def _munged(value: int) -> int:
    return OVERFLOW_ID if value == INVALID_ID else value


_TIMEOUT_UNITS = ((60, 1, "s"), (60 * 60, 60, "m"), (60 * 60 * 24, 60 * 60, "h"),
                  (60 * 60 * 24 * 7, 60 * 60 * 24, "d"))


def proc_timeout(expiry: int, now: Optional[int]) -> str:
    """``proc_keys_show()`` timeout column: perm / expd / <n>s|m|h|d|w relative to ``now``
    (the image's ``ktime_get_real_seconds()``); ``exp@<epoch>`` when ``now`` is unknown."""
    if not expiry:
        return "perm"
    if now is None:
        return "exp@%d" % expiry
    if now >= expiry:
        return "expd"
    left = expiry - now
    for bound, unit, suffix in _TIMEOUT_UNITS:
        if left < bound:
            return "%d%s" % (left // unit, suffix)
    return "%dw" % (left // (60 * 60 * 24 * 7))


def proc_keys_line(record: KeyRecord, now: Optional[int] = None) -> str:
    timeout = proc_timeout(record.expiry, now)
    return "%08x %s %5d %4s %08x %5d %5d %-9.9s %s" % (
        record.serial, proc_flags(record), record.usage, timeout, record.perm,
        _munged(record.uid), _munged(record.gid), record.type_name, record.describe)


def flag_names(flags: int) -> str:
    names = [name for bit, name in enumerate(KEY_FLAGS) if flags >> bit & 1]
    return "|".join(names) or "-"


def state_name(state: int) -> str:
    return {0: "uninstantiated", 1: "positive"}.get(state, "negative:%d" % state)


# --------------------------------------------------------------------------- the plugin


def _when(seconds: int) -> Any:
    if not seconds:
        return renderers.NotApplicableValue()
    try:
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return renderers.UnparsableValue()


class Keyring(interfaces.plugins.PluginInterface):
    """Lists every key in the kernel key serial tree and decodes its payload."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.ChoiceRequirement(
                name="export", choices=["keyctl"], optional=True,
                description="Write keyring.proc_keys.txt (/proc/keys format; every key in the tree, "
                            "NOT filtered by the reader's VIEW permission as the live file is)"),
            requirements.BooleanRequirement(
                name="dump_dir", optional=True, default=False,
                description="Write every readable payload (and decoded secret) to the output directory"),
            requirements.BooleanRequirement(
                name="no_dmcrypt_cross", optional=True, default=False,
                description="Skip the linux.dmcrypt cross-check of cryptsetup volume keys"),
            requirements.BooleanRequirement(
                name="verbose", optional=True, default=False,
                description="Full payloads plus Holders (tasks whose cred holds the keyring) and Detail"),
        ]

    # ------------------------------------------------------------------ setup

    def _setup(self) -> None:
        self.vmlinux, self.layer, self.reader = kernel_reader(self.context, self.config["kernel"])
        self.kl = KeyLayout.from_module(self.vmlinux)
        if self.kl.defaulted():
            vollog.warning("ISF lacks %d key offsets, guessed from the LP64 6.8 layout: %s",
                           len(self.kl.defaulted()), ", ".join(self.kl.defaulted()))

    # ------------------------------------------------------------------ records

    def _collect(self) -> List[KeyRecord]:
        root = symbol_address(self.vmlinux, "key_serial_tree")
        if root is None:
            vollog.warning("key_serial_tree not in the symbol table (CONFIG_KEYS off?)")
            return []
        walk_guessed = [k for k in WALK_KEYS if k in self.kl.defaulted()]
        if walk_guessed:
            vollog.warning("walking with guessed offsets: %s", ", ".join(walk_guessed))
        records = list(iter_keys(self.reader, self.kl, root))
        dm_keys = self._dmcrypt_keys(records)
        for record in records:
            self._decode(record, dm_keys)
        if self.config.get("verbose"):
            self._attach_holders(records)
        return records

    def _decode(self, record: KeyRecord, dm_keys: Dict[str, List[Tuple[bytes, str]]]) -> None:
        name, reader, kl = record.type_name, self.reader, self.kl
        record.describe = record.description
        if name == "keyring":
            members = keyring_members(reader, kl, record)
            record.semantics = "keyring members=%s" % (members if members is not None else "?")
            if record.state == 1:
                record.describe += (": %d" % members) if members else ": empty"
            return
        if name == "asymmetric":
            tail = asymmetric_describe(reader, kl, record)
            record.semantics = "asymmetric " + (tail.split(" ")[0] if tail else "?")
            record.describe += (": " + tail) if tail else ""
            return
        if name in ("user", "logon", "big_key", "encrypted", "trusted", "fscrypt-provisioning"):
            if record.state == 1:
                record.describe += ": %d" % record.datalen
        if name in ("user", "logon"):
            decode_user_payload(reader, kl, record)
            self._label_user(record, dm_keys)
        elif name == "encrypted":
            decode_encrypted(reader, kl, record)
        elif name == "fscrypt-provisioning":
            decode_provisioning(reader, kl, record)
        elif name == "trusted":
            record.semantics = "trusted (TPM-sealed; not decoded)"
        elif name == ".fscrypt":
            claim = FSCRYPT_CLAIM_RE.match(_ascii(record))
            record.semantics = ("fscrypt-v2-user-claim id=%s uid=%s (master key in the superblock "
                                "fscrypt_keyring, not a struct key)" % claim.groups()) if claim else "fscrypt"

    def _label_user(self, record: KeyRecord, dm_keys: Dict[str, List[Tuple[bytes, str]]]) -> None:
        if record.status not in (DECODED, UNVERIFIED):
            return
        if is_cryptsetup_volume_key(record) and decode_dmcrypt(record, dm_keys):
            return
        if record.type_name == "logon" and decode_fscrypt_v1(self.kl, record):
            return
        if record.type_name == "user" and decode_ecryptfs(self.kl, record):
            return
        record.semantics = "%s %dB" % (record.type_name, len(record.payload or b""))

    # ------------------------------------------------------------------ cross-checks

    def _dmcrypt_keys(self, records: List[KeyRecord]) -> Dict[str, List[Tuple[bytes, str]]]:
        """De-dashed LUKS UUID -> [(key, verdict status)] from ``linux.dmcrypt`` (O1/no O2 scan)."""
        if self.config.get("no_dmcrypt_cross") or not any(is_cryptsetup_volume_key(r) for r in records):
            return {}
        try:
            dm = self._dmcrypt_plugin()
            dm._setup()
            dm.offsets = dm._load_offsets()
            dm._setup_layout()
            dm_records = dm._records()
        except (exceptions.VolatilityException, OSError, ValueError, KeyError, AttributeError,
                TypeError) as error:
            vollog.warning("linux.dmcrypt cross-check unavailable: %s", error)
            return {}
        keys: Dict[str, List[Tuple[bytes, str]]] = {}
        for dm_record in dm_records:
            uuid = dmcrypt.luks_uuid_from_dm(dm_record["device"].uuid)
            verdict = dmcrypt.decide(dm_record["recovery"], None, dm.kl.key_path_defaulted())
            if uuid and verdict.key:
                keys.setdefault(uuid, []).append((verdict.key, verdict.status))
        vollog.info("dmcrypt cross-check: %d LUKS devices with a recovered key", len(keys))
        return keys

    def _dmcrypt_plugin(self) -> "dmcrypt.DmCrypt":
        sub = interfaces.configuration.path_join(self.config_path, "dmcrypt_cross")
        self.context.config[interfaces.configuration.path_join(sub, "kernel")] = self.config["kernel"]
        return dmcrypt.DmCrypt(self.context, sub, self._progress_callback)

    def _attach_holders(self, records: List[KeyRecord]) -> None:
        """Tasks whose cred names a key as its thread/process/session keyring (verbose only)."""
        from volatility3.plugins.linux import pslist  # lazy: only the verbose path needs it

        try:
            tasks = pslist.PsList.list_tasks(self.context, self.config["kernel"], include_threads=True)
            attribute_holders(self.reader, self.kl, records, tasks)
        except (exceptions.VolatilityException, AttributeError, KeyError, ValueError, TypeError):
            vollog.debug("task walk for keyring holders failed", exc_info=True)

    # ------------------------------------------------------------------ output

    def _payload_text(self, record: KeyRecord) -> Any:
        data = record.secret if record.secret is not None else record.payload
        if not data:
            return renderers.NotApplicableValue()
        if self.config.get("verbose") or self.config.get("dump_dir") or len(data) <= PREVIEW_BYTES:
            return data.hex()
        return "%s...(%dB)" % (data[:PREVIEW_BYTES].hex(), len(data))

    def _row(self, record: KeyRecord) -> Tuple:
        na = renderers.NotApplicableValue()
        row = [
            format_hints.Hex(record.serial), record.type_name, record.description or na,
            record.uid, record.gid, "%08x" % record.perm, state_name(record.state),
            flag_names(record.flags), record.datalen, _when(record.expiry), _when(record.last_used),
            record.semantics or na, record.status, self._payload_text(record),
            format_hints.Hex(record.address),
        ]
        if self.config.get("verbose"):
            row += [", ".join(record.holders) or na, record.detail or na]
        return tuple(row)

    def _columns(self) -> List[Tuple[str, Any]]:
        columns = [("Serial", format_hints.Hex), ("Type", str), ("Description", str), ("UID", int),
                   ("GID", int), ("Perm", str), ("State", str), ("Flags", str), ("Datalen", int),
                   ("Expiry", datetime.datetime), ("LastUsed", datetime.datetime),
                   ("Semantics", str), ("Status", str), ("Payload", str), ("Offset(V)", format_hints.Hex)]
        if self.config.get("verbose"):
            columns += [("Holders", str), ("Detail", str)]
        return columns

    def _image_now(self) -> Optional[int]:
        """``tk_core.timekeeper.xtime_sec`` -- the image's wall-clock seconds -- or None."""
        try:
            symbol = self.vmlinux.get_symbol("tk_core")
            inner = find_member(self.vmlinux, symbol.type, "timekeeper")
            xtime = find_member(self.vmlinux, self.vmlinux.get_type("timekeeper"), "xtime_sec")
        except (exceptions.SymbolError, AttributeError, KeyError, ValueError, TypeError):
            return None
        if inner is None or xtime is None:
            return None
        return self.reader.u64(self.vmlinux.offset + symbol.address + inner + xtime) or None

    def _export_keyctl(self, records: List[KeyRecord]) -> None:
        now = self._image_now()
        if now is None:
            vollog.warning("tk_core unreadable: keyctl export prints exp@<epoch> instead of a timeout")
        # Not VIEW-filtered: the live /proc/keys hides keys the reading task may not view.
        lines = [proc_keys_line(r, now) for r in records]
        with self.open("keyring.proc_keys.txt") as handle:
            handle.write(("\n".join(lines) + "\n").encode("utf-8"))

    def _dump(self, records: List[KeyRecord]) -> None:
        for record in records:
            safe_type = re.sub(r"[^A-Za-z0-9_.-]", "_", record.type_name)
            if record.payload:
                with self.open("keyring.%08x.%s.payload" % (record.serial, safe_type)) as handle:
                    handle.write(record.payload)
            if record.secret and record.secret != record.payload:
                with self.open("keyring.%08x.%s.secret" % (record.serial, safe_type)) as handle:
                    handle.write(record.secret)

    def _generator(self, records: List[KeyRecord]) -> Iterator[Tuple[int, Tuple]]:
        for record in records:
            yield 0, self._row(record)

    def run(self) -> renderers.TreeGrid:
        self._setup()
        records = self._collect()
        statuses = [r.status for r in records]
        vollog.info("linux.keyring: %d keys, %d with payload, %d proven (%s)", len(records),
                    sum(1 for r in records if r.payload), statuses.count(PROVEN), arch_of(self.layer))
        if self.config.get("export") == "keyctl":
            self._export_keyctl(records)
        if self.config.get("dump_dir"):
            self._dump(records)
        return renderers.TreeGrid(self._columns(), self._generator(records))


HOLDER_SLOTS = ("cred.thread_keyring", "cred.process_keyring", "cred.session_keyring")


def attribute_holders(reader: SafeReader, kl: KeyLayout, records: List[KeyRecord], tasks: Any) -> int:
    """Name each keyring after the tasks whose cred points at it; a smeared task is skipped,
    never fatal.  Returns the number of tasks skipped."""
    by_address = {r.address: r for r in records}
    skipped = 0
    for task in tasks:
        try:
            cred, label = int(task.cred), "%s(%d)" % (_comm(task), int(task.pid))
        except (exceptions.VolatilityException, AttributeError, TypeError, ValueError, OverflowError):
            skipped += 1
            continue
        for slot in HOLDER_SLOTS if cred else ():
            record = by_address.get(reader.ptr(cred + kl[slot]) or 0)
            if record is not None and label not in record.holders and len(record.holders) < 16:
                record.holders.append(label)
    return skipped


def _comm(task: Any) -> str:
    try:
        return task.comm.cast("string", max_length=16, errors="replace")
    except (exceptions.VolatilityException, AttributeError, TypeError, ValueError):
        return "?"
