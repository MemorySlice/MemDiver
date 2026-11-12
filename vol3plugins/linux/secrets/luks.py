"""LUKS1/LUKS2 header parser, volume-key digest oracle and dm-crypt cipher-spec parser.

Self-contained on purpose: the only imports are from the Python standard library, there are
no relative imports and nothing reads ``__file__``, so this file can be pasted verbatim into
another module (the generated Volatility 3 plugins inline it as source).  Annotations use
``typing`` generics rather than ``X | None`` so the paste also runs on older interpreters.

What it does
------------
* ``find_luks_headers``  -- locate plausible LUKS headers inside a memory image.
* ``parse_luks1`` / ``parse_luks2`` / ``parse_luks`` -- decode a header.
* ``verify_volume_key``  -- the oracle: a recovered dm-crypt volume key is correct iff the
  PBKDF2 digest of it equals the digest stored in the header.  No keyslot passphrase and no
  ciphertext is needed, and a false positive costs one PBKDF2 of ~1e5 iterations.
* ``segment_crypto``     -- what a ``dmsetup table`` line needs for each data segment.
* ``parse_cipher_spec``  -- dm-crypt's cipher string -> kernel crypto-API template name.

Format references
-----------------
LUKS1 on-disk format (``struct luks_phdr``, all integers big-endian, 592 bytes)::

    0   magic[6] "LUKS\\xba\\xbe"   6  version u16 (=1)        8  cipherName[32]
    40  cipherMode[32]            72  hashSpec[32]            104 payloadOffset u32 (512 B sectors)
    108 keyBytes u32              112 mkDigest[20]            132 mkDigestSalt[32]
    164 mkDigestIterations u32    168 uuid[40]                208 8 x keyblock (48 B each):
        active u32 (0x00AC71F3 enabled / 0x0000DEAD disabled), passwordIterations u32,
        passwordSalt[32], keyMaterialOffset u32 (sectors), stripes u32

    mkDigest = PBKDF2-HMAC(hashSpec, volume_key, mkDigestSalt, mkDigestIterations, dkLen=20)

    Source: "LUKS On-Disk Format Specification v1.2.3" (cryptsetup wiki, LUKS-standard), and
    ``lib/luks1/luks.h`` in the cryptsetup tree.

LUKS2 on-disk format (``struct luks2_hdr_disk``, big-endian, 4096-byte binary header
followed by a NUL-terminated JSON area; ``hdr_size`` covers both)::

    0 magic[6] "LUKS\\xba\\xbe" (primary) or "SKUL\\xba\\xbe" (secondary copy)
    6 version u16 (=2)   8 hdr_size u64   16 seqid u64   24 label[48]   72 checksum_alg[32]
    104 salt[64]   168 uuid[40]   208 subsystem[48]   256 hdr_offset u64   264 padding[184]
    448 csum[64]   512 padding up to 4096

    csum = H(header[0:hdr_size] with the 64-byte csum field set to zero), H = checksum_alg
    (sha256 in practice), stored left-aligned in the 64-byte field.  Binary header and JSON
    area are hashed together.

    A ``pbkdf2`` digest entry in the JSON ``digests`` object is
    base64(PBKDF2-HMAC(hash, volume_key, base64(salt), iterations, dkLen=len(digest))).

    Source: "LUKS2 On-Disk Format Specification" (cryptsetup/LUKS2-docs, luks2_doc_wip.pdf),
    cryptsetup ``lib/luks2/luks2_disk_metadata.c`` (``hdr_checksum_calculate``) and
    ``lib/luks2/luks2.h``.  The field offsets and the checksum rule above were additionally
    verified byte-for-byte against real ``cryptsetup 2.7.0`` headers (see
    ``tests/fixtures/luks/README.md``): the checksum validates on primary and secondary copies.

dm-crypt cipher strings: ``crypt_ctr_cipher`` / ``crypt_ctr_cipher_old`` /
``crypt_ctr_cipher_new`` / ``crypt_ctr_ivmode`` in the Linux kernel's
``drivers/md/dm-crypt.c`` (read at linux master, 2026-11-06).
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

__all__ = [
    "LUKS_MAGIC",
    "LUKS2_SECONDARY_MAGIC",
    "LuksParseError",
    "Luks1KeySlot",
    "Luks1Header",
    "Luks2Header",
    "VolumeKeyVerdict",
    "CipherSpec",
    "find_luks_headers",
    "parse_luks1",
    "parse_luks2",
    "parse_luks",
    "luks2_from_document",
    "verify_volume_key",
    "segment_crypto",
    "parse_cipher_spec",
]

LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS2_SECONDARY_MAGIC = b"SKUL\xba\xbe"

LUKS1_HEADER_SIZE = 592
LUKS1_NUM_KEYSLOTS = 8
LUKS1_KEY_ENABLED = 0x00AC71F3
LUKS1_KEY_DISABLED = 0x0000DEAD
LUKS1_SECTOR_BYTES = 512
LUKS1_DIGEST_BYTES = 20

LUKS2_BINARY_HEADER_SIZE = 4096
LUKS2_CSUM_OFFSET = 448
LUKS2_CSUM_LENGTH = 64
LUKS2_HDR_SIZES = frozenset(1 << shift for shift in range(14, 23))  # 16 KiB .. 4 MiB

DEFAULT_MAX_PBKDF2_ITERATIONS = 20_000_000
DEFAULT_SEGMENT_SECTOR_BYTES = 512
CRYPTO_MAX_ALG_NAME = 128  # include/linux/crypto.h: longest kernel crypto-API name

# Fixed-layout prefixes, big-endian, no padding.
_LUKS1_PREFIX = struct.Struct(">6sH32s32s32sII20s32sI40s")  # 208 bytes
_LUKS1_KEYBLOCK = struct.Struct(">II32sII")  # 48 bytes
_LUKS2_PREFIX = struct.Struct(">6sHQQ48s32s64s40s48sQ")  # 264 bytes

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CAPI_TEMPLATE_RE = re.compile(r"([A-Za-z0-9_.-]+)\(([A-Za-z0-9_.-]+)\)")
_DIGITS_RE = re.compile(r"[0-9]+")
_ID_RE = re.compile(r"[0-9]{1,9}")  # ASCII only, bounded: str.isdigit() accepts "\u00b2"
_NUMBER_RE = re.compile(r"[0-9]{1,18}")
MAX_JSON_DEPTH = 32
MAX_PBKDF2_DIGESTS = 8
DEFAULT_MAX_TOTAL_ITERATIONS = 40_000_000
MIN_DIGEST_BYTES = 16
MAX_DIGEST_BYTES = 64
_CHECKSUM_ALGS = frozenset({"sha256", "sha1", "sha512"})

# IV modes accepted by crypt_ctr_ivmode(); anything else is "Invalid IV mode".
_DM_CRYPT_IV_MODES = frozenset(
    {"plain", "plain64", "plain64be", "essiv", "benbi", "null", "eboiv", "elephant",
     "lmk", "tcw", "random"}
)


class LuksParseError(ValueError):
    """The buffer is not a parseable LUKS header."""


# --------------------------------------------------------------------------- dataclasses


@dataclass(frozen=True)
class Luks1KeySlot:
    index: int
    active: bool
    raw_active: int
    iterations: int
    salt: bytes
    key_material_offset: int  # 512-byte sectors from the start of the device
    stripes: int


@dataclass(frozen=True)
class Luks1Header:
    cipher_name: str
    cipher_mode: str
    hash_spec: str
    payload_offset_sectors: int
    key_bytes: int
    mk_digest: bytes
    mk_digest_salt: bytes
    mk_digest_iter: int
    uuid: str
    keyslots: List[Luks1KeySlot]
    version: int = 1

    @property
    def cipher(self) -> str:
        """dm-crypt form, e.g. ``aes-xts-plain64``."""
        return "%s-%s" % (self.cipher_name, self.cipher_mode)

    @property
    def payload_offset_bytes(self) -> int:
        return self.payload_offset_sectors * LUKS1_SECTOR_BYTES


@dataclass(frozen=True)
class Luks2Header:
    magic: bytes
    version: int
    hdr_size: int
    seqid: int
    label: str
    checksum_alg: str
    salt: bytes
    uuid: str
    subsystem: str
    hdr_offset: int
    csum: bytes
    checksum_ok: bool
    complete: bool  # the buffer held all hdr_size bytes (JSON area present)
    is_secondary: bool  # parsed from the "SKUL" copy
    json_text: Optional[str] = None
    json_error: Optional[str] = None
    keyslots: Dict[str, Any] = field(default_factory=dict)
    segments: Dict[str, Any] = field(default_factory=dict)
    digests: Dict[str, Any] = field(default_factory=dict)
    tokens: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VolumeKeyVerdict:
    matched: bool
    digest_id: Optional[str]  # LUKS1 has one implicit digest and is reported as "0"
    segments: List[Dict[str, Any]]  # segment_crypto() entries bound to the matched digest
    detail: str
    # True when a PBKDF2 was NOT run because the iteration count exceeds max_iterations or the
    # total budget: "not tested", which a caller must not read as "wrong key".
    refused: bool = False


@dataclass(frozen=True)
class CipherSpec:
    cipher: Optional[str]
    chainmode: Optional[str]
    ivmode: Optional[str]
    ivopts: Optional[str]
    key_parts: int
    crypto_api_name: str


# --------------------------------------------------------------------------- small helpers


def _to_bytes(buf: Any, need: int, what: str) -> bytes:
    """First ``need`` bytes of ``buf`` (bytes-like) or raise ``LuksParseError``."""
    try:
        view = memoryview(buf)
    except TypeError:
        raise LuksParseError("%s: buffer is not bytes-like" % what)
    if len(view) < need:
        raise LuksParseError("%s needs %d bytes, got %d" % (what, need, len(view)))
    return bytes(view[:need])


def _decode_field(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _ascii_field(raw: bytes, allow_empty: bool = False) -> bool:
    """True when ``raw`` is NUL-terminated printable ASCII (the sanity test for strings)."""
    end = raw.find(b"\0")
    if end < 0:
        return False
    text = raw[:end]
    if not text and not allow_empty:
        return False
    return all(0x20 <= byte <= 0x7E for byte in text)


def _natural_ids(mapping: Dict[str, Any]) -> List[str]:
    def order(key: Any) -> Tuple[int, int, str]:
        text = str(key)
        return (0, int(text), text) if _ID_RE.fullmatch(text) else (1, 0, text)

    return sorted(mapping, key=order)


def _as_list(value: Any) -> List[Any]:
    """JSON from a carved header is untrusted: anything that is not a list counts as empty."""
    return value if isinstance(value, list) else []


def _to_int(value: Any, default: int = 0) -> int:
    """A real non-negative int (or a short decimal string); floats, bools, inf -> default."""
    if isinstance(value, str) and _NUMBER_RE.fullmatch(value):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 63:
        return default
    return value


# --------------------------------------------------------------------------- header search


def _luks1_slots_plausible(chunk: bytes) -> bool:
    states = (LUKS1_KEY_ENABLED, LUKS1_KEY_DISABLED)
    for index in range(LUKS1_NUM_KEYSLOTS):
        offset = _LUKS1_PREFIX.size + index * _LUKS1_KEYBLOCK.size
        if struct.unpack_from(">I", chunk, offset)[0] not in states:
            return False
    return True


def _plausible_luks1(chunk: bytes) -> bool:
    if len(chunk) < LUKS1_HEADER_SIZE:
        return False
    fields = _LUKS1_PREFIX.unpack_from(chunk)
    name, mode, hash_spec = fields[2], fields[3], fields[4]
    key_bytes, mk_iterations, uuid = fields[6], fields[9], fields[10]
    return (
        all(_ascii_field(raw) for raw in (name, mode, hash_spec))
        and 8 <= key_bytes <= 512
        and mk_iterations >= 1
        and _ascii_field(uuid)
        and bool(_UUID_RE.fullmatch(_decode_field(uuid)))
        and _luks1_slots_plausible(chunk)
    )


def _plausible_luks2(chunk: bytes) -> bool:
    if len(chunk) < _LUKS2_PREFIX.size:
        return False
    _, _, hdr_size, _, label, alg, _, uuid, subsystem, hdr_offset = _LUKS2_PREFIX.unpack_from(chunk)
    return (
        hdr_size in LUKS2_HDR_SIZES
        and _ascii_field(alg)
        and _ascii_field(label, allow_empty=True)
        and _ascii_field(subsystem, allow_empty=True)
        and _ascii_field(uuid)
        and bool(_UUID_RE.fullmatch(_decode_field(uuid)))
        and hdr_offset % 4096 == 0
    )


def _plausible_header_at(data: Any, position: int) -> bool:
    chunk = bytes(data[position:position + LUKS1_HEADER_SIZE])
    if len(chunk) < 8:
        return False
    version = struct.unpack_from(">H", chunk, 6)[0]
    if version == 1 and chunk[:6] == LUKS_MAGIC:
        return _plausible_luks1(chunk)
    if version == 2:
        return _plausible_luks2(chunk)
    return False


def _finder(data: Any):
    return data.find if hasattr(data, "find") else bytes(data).find


def find_luks_headers(data: Any, base: int = 0) -> List[int]:
    """Offsets (plus ``base``) of plausible LUKS headers in ``data``.

    A hit needs the magic, version 1 or 2 and sane fields (printable NUL-terminated strings,
    canonical UUID, valid keyslot state words / header size).  LUKS2 secondary copies (magic
    ``SKUL``) are reported too.  LUKS1 needs 592 bytes after the magic, LUKS2 264, so a caller
    scanning in chunks should overlap them by at least 592 bytes.
    """
    find = _finder(data)
    hits = []
    for magic in (LUKS_MAGIC, LUKS2_SECONDARY_MAGIC):
        position = find(magic)
        while position != -1:
            if _plausible_header_at(data, position):
                hits.append(base + position)
            position = find(magic, position + 1)
    return sorted(hits)


# --------------------------------------------------------------------------- LUKS1


def _parse_luks1_keyslot(index: int, data: bytes) -> Luks1KeySlot:
    offset = _LUKS1_PREFIX.size + index * _LUKS1_KEYBLOCK.size
    active, iterations, salt, key_material_offset, stripes = _LUKS1_KEYBLOCK.unpack_from(data, offset)
    return Luks1KeySlot(
        index=index,
        active=active == LUKS1_KEY_ENABLED,
        raw_active=active,
        iterations=iterations,
        salt=salt,
        key_material_offset=key_material_offset,
        stripes=stripes,
    )


def parse_luks1(buf: Any) -> Luks1Header:
    """Decode the 592-byte LUKS1 header at the start of ``buf``."""
    data = _to_bytes(buf, LUKS1_HEADER_SIZE, "LUKS1 header")
    (magic, version, name, mode, hash_spec, payload, key_bytes, mk_digest, mk_salt,
     mk_iterations, uuid) = _LUKS1_PREFIX.unpack_from(data)
    if magic != LUKS_MAGIC or version != 1:
        raise LuksParseError("not a LUKS1 header (magic %r, version %d)" % (magic, version))
    slots = [_parse_luks1_keyslot(index, data) for index in range(LUKS1_NUM_KEYSLOTS)]
    return Luks1Header(
        cipher_name=_decode_field(name),
        cipher_mode=_decode_field(mode),
        hash_spec=_decode_field(hash_spec),
        payload_offset_sectors=payload,
        key_bytes=key_bytes,
        mk_digest=mk_digest,
        mk_digest_salt=mk_salt,
        mk_digest_iter=mk_iterations,
        uuid=_decode_field(uuid),
        keyslots=slots,
    )


# --------------------------------------------------------------------------- LUKS2


def _luks2_checksum_ok(area: bytes, alg: str, csum: bytes) -> bool:
    """csum == H(area with the 64-byte csum field zeroed); see the module docstring."""
    if alg not in _CHECKSUM_ALGS:
        return False
    try:
        digest = hashlib.new(alg)
    except (ValueError, TypeError):
        return False
    digest.update(area[:LUKS2_CSUM_OFFSET])
    digest.update(b"\0" * LUKS2_CSUM_LENGTH)
    digest.update(area[LUKS2_CSUM_OFFSET + LUKS2_CSUM_LENGTH:])
    return hmac.compare_digest(digest.digest(), csum[:digest.digest_size])


def _json_depth_ok(raw: bytes) -> bool:
    """Nesting depth <= MAX_JSON_DEPTH, counted outside strings (json.loads recurses)."""
    depth, in_string, escaped = 0, False, False
    for byte in raw:
        if in_string:
            in_string, escaped = (byte != 0x22 or escaped), (byte == 0x5C and not escaped)
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return True


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite JSON constant %s" % name)


def _finite_float(text: str) -> float:
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("non-finite JSON number")
    return value


def _parse_luks2_json(json_area: bytes) -> Tuple[str, Dict[str, Any], Optional[str]]:
    raw = json_area.split(b"\0", 1)[0]
    try:
        if not _json_depth_ok(raw):
            raise ValueError("JSON nesting deeper than %d" % MAX_JSON_DEPTH)
        text = raw.decode("utf-8")
        document = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
        if not isinstance(document, dict):
            raise ValueError("JSON area is not an object")
    except (ValueError, RecursionError) as error:  # decode/JSON errors are ValueErrors
        return raw.decode("utf-8", "replace"), {}, str(error)
    return text, document, None


def _json_section(document: Dict[str, Any], name: str) -> Dict[str, Any]:
    section = document.get(name)
    return section if isinstance(section, dict) else {}


def parse_luks2(buf: Any) -> Luks2Header:
    """Decode a LUKS2 header (primary ``LUKS`` or secondary ``SKUL``) at the start of ``buf``.

    ``buf`` must hold at least the 4096-byte binary header; if it holds fewer than ``hdr_size``
    bytes the JSON sections stay empty and ``complete``/``checksum_ok`` are False.  A corrupt
    JSON area does not raise: ``json_error`` says why and ``checksum_ok`` is False.
    """
    head = _to_bytes(buf, LUKS2_BINARY_HEADER_SIZE, "LUKS2 binary header")
    (magic, version, hdr_size, seqid, label, alg, salt, uuid, subsystem,
     hdr_offset) = _LUKS2_PREFIX.unpack_from(head)
    if magic not in (LUKS_MAGIC, LUKS2_SECONDARY_MAGIC) or version != 2:
        raise LuksParseError("not a LUKS2 header (magic %r, version %d)" % (magic, version))
    if hdr_size not in LUKS2_HDR_SIZES:
        raise LuksParseError("implausible LUKS2 hdr_size %d" % hdr_size)
    complete = len(memoryview(buf)) >= hdr_size
    area = bytes(memoryview(buf)[:hdr_size]) if complete else head
    csum = head[LUKS2_CSUM_OFFSET:LUKS2_CSUM_OFFSET + LUKS2_CSUM_LENGTH]
    algorithm = _decode_field(alg)
    text, document, error = _parse_luks2_json(area[LUKS2_BINARY_HEADER_SIZE:]) if complete \
        else (None, {}, None)
    return Luks2Header(
        magic=magic, version=version, hdr_size=hdr_size, seqid=seqid,
        label=_decode_field(label), checksum_alg=algorithm, salt=salt, uuid=_decode_field(uuid),
        subsystem=_decode_field(subsystem), hdr_offset=hdr_offset, csum=csum,
        checksum_ok=complete and _luks2_checksum_ok(area, algorithm, csum),
        complete=complete, is_secondary=magic == LUKS2_SECONDARY_MAGIC,
        json_text=text, json_error=error,
        keyslots=_json_section(document, "keyslots"), segments=_json_section(document, "segments"),
        digests=_json_section(document, "digests"), tokens=_json_section(document, "tokens"),
        config=_json_section(document, "config"),
    )


def luks2_from_document(document: Any) -> Luks2Header:
    """A ``Luks2Header`` from a TRUSTED LUKS2 JSON document, without the binary header.

    ``document`` is the JSON area as a dict, ``str`` or ``bytes`` (a compact copy holding at
    least ``digests``; ``keyslots``, ``segments``, ``config``, ``tokens`` and a top-level
    ``uuid`` are used when present).  There is no binary header, so no checksum is checked
    (``checksum_ok`` is False and ``hdr_size`` 0): the caller vouches for the document.  The
    result is ``complete``, so ``verify_volume_key`` and ``segment_crypto`` work on it.
    Raises ``LuksParseError`` for anything that is not a JSON object.
    """
    if isinstance(document, (bytes, bytearray, memoryview, str)):
        raw = document.encode("utf-8") if isinstance(document, str) else bytes(document)
        text, document, error = _parse_luks2_json(raw)
        if error is not None:
            raise LuksParseError("LUKS2 JSON document: %s" % error)
    if not isinstance(document, dict):
        raise LuksParseError("a LUKS2 JSON document is an object, not %s" % type(document).__name__)
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    uuid = document.get("uuid")
    return Luks2Header(
        magic=LUKS_MAGIC, version=2, hdr_size=0, seqid=0, label="", checksum_alg="", salt=b"",
        uuid=uuid if isinstance(uuid, str) else "", subsystem="", hdr_offset=0, csum=b"",
        checksum_ok=False, complete=True, is_secondary=False, json_text=text, json_error=None,
        keyslots=_json_section(document, "keyslots"), segments=_json_section(document, "segments"),
        digests=_json_section(document, "digests"), tokens=_json_section(document, "tokens"),
        config=_json_section(document, "config"),
    )


def parse_luks(buf: Any) -> Union[Luks1Header, Luks2Header]:
    """Dispatch on the header version: ``Luks1Header`` for version 1, ``Luks2Header`` for 2."""
    head = _to_bytes(buf, 8, "LUKS header")
    if head[:6] not in (LUKS_MAGIC, LUKS2_SECONDARY_MAGIC):
        raise LuksParseError("no LUKS magic at start of buffer")
    version = struct.unpack_from(">H", head, 6)[0]
    if version == 1:
        return parse_luks1(buf)
    if version == 2:
        return parse_luks2(buf)
    raise LuksParseError("unsupported LUKS version %d" % version)


# --------------------------------------------------------------------------- segments


def _luks2_digest_for_segment(header: Luks2Header, segment_id: str) -> Optional[str]:
    for digest_id in _natural_ids(header.digests):
        digest = header.digests[digest_id]
        if isinstance(digest, dict) and segment_id in [str(i) for i in _as_list(digest.get("segments"))]:
            return digest_id
    return None


def _luks2_key_bytes(header: Luks2Header, digest_id: Optional[str]) -> Optional[int]:
    digest = header.digests.get(digest_id) if digest_id is not None else None
    for slot_id in (_as_list(digest.get("keyslots")) if isinstance(digest, dict) else []):
        slot = header.keyslots.get(str(slot_id))
        if isinstance(slot, dict) and "key_size" in slot:
            return _to_int(slot["key_size"], 0) or None
    return None


def _luks2_segment_entry(header: Luks2Header, segment_id: str, segment: Dict[str, Any]) -> Dict[str, Any]:
    digest_id = _luks2_digest_for_segment(header, segment_id)
    size = str(segment.get("size", "dynamic"))
    return {
        "segment": segment_id,
        "type": segment.get("type"),
        "cipher": segment.get("encryption"),
        "sector_size": _to_int(segment.get("sector_size"), DEFAULT_SEGMENT_SECTOR_BYTES),
        "iv_tweak": _to_int(segment.get("iv_tweak"), 0),
        "offset_bytes": _to_int(segment.get("offset"), 0),
        "size": None if size == "dynamic" else _to_int(size, 0),
        "key_bytes": _luks2_key_bytes(header, digest_id),
        "digest_id": digest_id,
        "integrity": segment.get("integrity"),
        "flags": _as_list(segment.get("flags")),
    }


def segment_crypto(header: Any) -> List[Dict[str, Any]]:
    """One dict per ``crypt`` data segment, in the terms a ``dmsetup table`` line needs.

    Keys: ``segment`` (id string), ``type``, ``cipher`` (dm form, e.g. ``aes-xts-plain64``),
    ``sector_size`` (bytes; dm-crypt ``sector_size:N`` option), ``iv_tweak`` (dm-crypt
    ``iv_offset``), ``offset_bytes`` (start of data on the device; dm-crypt wants it in 512-byte
    sectors), ``size`` (bytes, or ``None`` for "dynamic" = to the end of the device),
    ``key_bytes`` (volume-key length, from the digest's keyslot), ``digest_id``, ``integrity``
    and ``flags``.  Non-``crypt`` segments (e.g. ``linear`` during re-encryption) are skipped.
    LUKS1 always has one implicit segment ``"0"`` with 512-byte sectors and iv_tweak 0.
    """
    if isinstance(header, Luks1Header):
        return [{
            "segment": "0", "type": "crypt", "cipher": header.cipher,
            "sector_size": LUKS1_SECTOR_BYTES, "iv_tweak": 0,
            "offset_bytes": header.payload_offset_bytes, "size": None,
            "key_bytes": header.key_bytes, "digest_id": "0", "integrity": None, "flags": [],
        }]
    if not isinstance(header, Luks2Header):
        raise LuksParseError("segment_crypto needs a Luks1Header or Luks2Header")
    entries = []
    for segment_id in _natural_ids(header.segments):
        segment = header.segments[segment_id]
        if isinstance(segment, dict) and segment.get("type") == "crypt":
            entries.append(_luks2_segment_entry(header, str(segment_id), segment))
    return entries


# --------------------------------------------------------------------------- the oracle


def _pbkdf2(hash_name: str, key: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac(hash_name, key, salt, iterations, length)


def _verify_luks1(header: Luks1Header, key: bytes, max_iterations: int,
                  budget: List[int]) -> VolumeKeyVerdict:
    if len(key) != header.key_bytes:
        return VolumeKeyVerdict(False, None, [], "key length %d != header key_bytes %d"
                                % (len(key), header.key_bytes))
    if not 0 < header.mk_digest_iter <= max_iterations:
        return VolumeKeyVerdict(False, None, [], "mk_digest_iter %d outside (0, %d]"
                                % (header.mk_digest_iter, max_iterations),
                                refused=header.mk_digest_iter > max_iterations)
    budget[0] -= header.mk_digest_iter
    if budget[0] < 0:
        return VolumeKeyVerdict(False, None, [], "total iteration budget exceeded", refused=True)
    try:
        candidate = _pbkdf2(header.hash_spec, key, header.mk_digest_salt, header.mk_digest_iter,
                            LUKS1_DIGEST_BYTES)
    except (ValueError, TypeError, OverflowError) as error:
        return VolumeKeyVerdict(False, None, [], "unsupported hash %r: %s" % (header.hash_spec, error))
    if not hmac.compare_digest(candidate, header.mk_digest):
        return VolumeKeyVerdict(False, None, [], "PBKDF2(%s) of key does not equal mk_digest"
                                % header.hash_spec)
    return VolumeKeyVerdict(True, "0", segment_crypto(header),
                            "PBKDF2-%s x%d of key == mk_digest" % (header.hash_spec, header.mk_digest_iter))


def _pbkdf2_digest_ids(header: Luks2Header) -> List[str]:
    return [
        digest_id for digest_id in _natural_ids(header.digests)
        if isinstance(header.digests[digest_id], dict) and header.digests[digest_id].get("type") == "pbkdf2"
    ]


def _expected_key_lengths(header: Luks2Header, digest: Dict[str, Any]) -> Set[int]:
    lengths = set()
    for slot_id in _as_list(digest.get("keyslots")):
        slot = header.keyslots.get(str(slot_id))
        if isinstance(slot, dict) and _to_int(slot.get("key_size"), 0) > 0:
            lengths.add(_to_int(slot["key_size"]))
    return lengths


def _check_luks2_digest(header: Luks2Header, digest: Dict[str, Any], key: bytes,
                        max_iterations: int, budget: List[int]) -> Optional[str]:
    """None when ``key`` matches ``digest``, else the reason it does not."""
    lengths = _expected_key_lengths(header, digest)
    if lengths and len(key) not in lengths:
        return "key length %d not in keyslot key_size %s" % (len(key), sorted(lengths))
    try:
        salt = base64.b64decode(digest["salt"], validate=True)
        expected = base64.b64decode(digest["digest"], validate=True)
        iterations = _to_int(digest["iterations"], 0)
        hash_name = str(digest["hash"])
    except (KeyError, TypeError, ValueError, binascii.Error) as error:
        return "malformed digest entry (%s)" % error
    if not 0 < iterations <= max_iterations:
        return "iterations %r outside (0, %d]" % (digest.get("iterations"), max_iterations)
    if not MIN_DIGEST_BYTES <= len(expected) <= MAX_DIGEST_BYTES:
        return "digest length %d outside [%d, %d]" % (len(expected), MIN_DIGEST_BYTES, MAX_DIGEST_BYTES)
    budget[0] -= iterations
    if budget[0] < 0:
        return "total iteration budget exceeded"
    try:
        candidate = _pbkdf2(hash_name, key, salt, iterations, len(expected))
    except (ValueError, TypeError, OverflowError) as error:
        return "unsupported hash %r: %s" % (hash_name, error)
    return None if hmac.compare_digest(candidate, expected) else "PBKDF2(%s) mismatch" % hash_name


def _verify_luks2(header: Luks2Header, key: bytes, max_iterations: int,
                  budget: List[int]) -> VolumeKeyVerdict:
    digest_ids = _pbkdf2_digest_ids(header)
    if not digest_ids:
        why = "JSON area unavailable" if not header.complete else "no pbkdf2 digest in header"
        return VolumeKeyVerdict(False, None, [], why)
    reasons = []
    for digest_id in digest_ids[:MAX_PBKDF2_DIGESTS]:
        reason = _check_luks2_digest(header, header.digests[digest_id], key, max_iterations, budget)
        if reason is None:
            bound = [seg for seg in segment_crypto(header) if seg["digest_id"] == digest_id]
            return VolumeKeyVerdict(True, digest_id, bound, "PBKDF2 digest %s matches" % digest_id)
        reasons.append("digest %s: %s" % (digest_id, reason))
    if len(digest_ids) > MAX_PBKDF2_DIGESTS:
        reasons.append("%d more pbkdf2 digests not tried" % (len(digest_ids) - MAX_PBKDF2_DIGESTS))
    refused = any(_is_refusal(reason, max_iterations) for reason in reasons)
    return VolumeKeyVerdict(False, None, [], "; ".join(reasons), refused=refused)


def _is_refusal(reason: str, max_iterations: int) -> bool:
    """A digest reason meaning "PBKDF2 not run because of the iteration limits"."""
    if reason.endswith("total iteration budget exceeded"):
        return True
    match = re.search(r"iterations '?(\d+)'? outside \(0, %d\]" % max_iterations, reason)
    return match is not None and int(match.group(1)) > max_iterations


def verify_volume_key(header: Any, key: Any, *,
                      max_iterations: int = DEFAULT_MAX_PBKDF2_ITERATIONS,
                      max_total_iterations: int = DEFAULT_MAX_TOTAL_ITERATIONS) -> VolumeKeyVerdict:
    """Does ``key`` equal the volume (master) key this header protects?

    LUKS1: ``PBKDF2(hash_spec, key, mk_digest_salt, mk_digest_iter, 20) == mk_digest``.
    LUKS2: the same test against every ``pbkdf2`` entry of ``digests``.  A key whose length
    differs from the header's key size is rejected before any PBKDF2 runs, and so is a header
    whose iteration count exceeds ``max_iterations`` (a header carved from a memory image is
    untrusted input and must not be able to stall the caller).

    Never raises: every problem is a ``matched=False`` verdict whose ``detail`` says why.  At
    most ``MAX_PBKDF2_DIGESTS`` digests are tried and at most ``max_total_iterations`` PBKDF2
    iterations are spent per call.
    """
    try:
        key = bytes(memoryview(key))
    except TypeError:
        return VolumeKeyVerdict(False, None, [], "key is not bytes-like")
    if not key:
        return VolumeKeyVerdict(False, None, [], "empty key")
    budget = [max_total_iterations]
    try:
        if isinstance(header, Luks1Header):
            return _verify_luks1(header, key, max_iterations, budget)
        if isinstance(header, Luks2Header):
            return _verify_luks2(header, key, max_iterations, budget)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as error:
        return VolumeKeyVerdict(False, None, [], "malformed header (%s: %s)" % (type(error).__name__, error))
    return VolumeKeyVerdict(False, None, [], "not a LUKS header (%s)" % type(header).__name__)


# --------------------------------------------------------------------------- cipher spec


def _split_old_cipher_spec(spec: str) -> Tuple[str, Optional[str], Optional[str], Optional[str], int]:
    """``cipher[:keycount]-chainmode-ivmode[:ivopts]`` as ``crypt_ctr_cipher_old`` splits it."""
    if "(" in spec:
        raise ValueError("Bad cipher specification: %r" % spec)
    head, has_rest, rest = spec.partition("-")
    cipher, has_count, keycount = head.partition(":")
    tfms_count = 1
    if has_count:
        count = int(keycount) if _DIGITS_RE.fullmatch(keycount) else 0
        if count == 0 or count & (count - 1):
            raise ValueError("Bad cipher key count specification: %r" % keycount)
        tfms_count = count
    chainmode: Optional[str] = None
    ivmode: Optional[str] = None
    ivopts: Optional[str] = None
    if has_rest:
        chainmode, has_iv, tail = rest.partition("-")
        if has_iv:
            ivmode, has_opts, opts = tail.partition(":")
            ivopts = opts if has_opts else None
    if chainmode is None or (chainmode == "plain" and ivmode is None):
        chainmode, ivmode = "cbc", "plain"  # the original dm-crypt default
    if chainmode != "ecb" and ivmode is None:
        raise ValueError("IV mechanism required")
    if not cipher or not chainmode:
        raise ValueError("Bad cipher specification: %r" % spec)
    return cipher, chainmode, ivmode, ivopts, tfms_count


def _split_capi_cipher_spec(spec: str) -> Tuple[str, Optional[str], Optional[str], int]:
    """``capi:crypto_api_spec-ivmode:ivopts`` as ``crypt_ctr_cipher_new`` splits it."""
    api = spec[len("capi:"):]
    ivopts: Optional[str] = None
    ivmode: Optional[str] = None
    if ":" in api:  # last ':' -- ivopts may itself contain '-' (a hash name)
        api, _, ivopts = api.rpartition(":")
    if "-" in api:
        api, _, ivmode = api.rpartition("-")
    return api, ivmode, ivopts, 64 if ivmode == "lmk" else 1


def _capi_cipher_and_mode(api: str) -> Tuple[Optional[str], Optional[str]]:
    match = _CAPI_TEMPLATE_RE.fullmatch(api)
    if match:
        return match.group(2), match.group(1)  # xts(aes) -> cipher aes, chainmode xts
    return None, None


def _key_parts_for_ivmode(ivmode: Optional[str], tfms_count: int, key_size: Optional[int]) -> int:
    """``cc->key_parts`` after ``crypt_ctr_ivmode`` (elephant=2, lmk +1 if uneven, tcw +2)."""
    if ivmode == "elephant":
        return 2
    if ivmode == "tcw":
        return tfms_count + 2
    if ivmode == "lmk" and key_size is not None and key_size % tfms_count:
        return tfms_count + 1
    return tfms_count


def parse_cipher_spec(spec: str, key_size: Optional[int] = None) -> CipherSpec:
    """Parse a dm-crypt cipher string the way the kernel does.

    * Legacy ``cipher[:keycount]-chainmode-ivmode[:ivopts]`` (``crypt_ctr_cipher_old``):
      ``aes-xts-plain64`` -> ``xts(aes)``; ``aes-cbc-essiv:sha256`` -> the ESSIV template
      ``essiv(cbc(aes),sha256)``; a bare cipher name means ``cbc-plain``.
    * ``capi:<crypto api spec>[-ivmode[:ivopts]]`` (``crypt_ctr_cipher_new``) passes the API
      spec through (``capi:xts(aes)-plain64`` -> ``xts(aes)``); ``essiv`` wraps it as
      ``essiv(<spec>,<ivopts>)``.
    * ``key_parts`` mirrors ``cc->key_parts``: the legacy ``keycount`` (default 1), forced to
      64 for ``capi:...-lmk``, 2 for ``elephant``, +2 for ``tcw`` (IV seed + whitening) and +1
      for ``lmk`` when ``key_size`` (bytes) is given and is not a multiple of the key count.
      For ``lmk`` without ``key_size`` that last +1 cannot be decided and is not applied.
    * ``ecb`` takes no IV, so ``ivmode`` is reported as ``None`` for it (dm-crypt drops it too).

    Raises ``ValueError`` where dm-crypt would reject the string (bad key count, missing IV
    mechanism, missing ESSIV digest, unknown IV mode, over-long API name).
    """
    if spec.startswith("capi:"):
        api, ivmode, ivopts, tfms_count = _split_capi_cipher_spec(spec)
        cipher, chainmode = _capi_cipher_and_mode(api)
    else:
        cipher, chainmode, ivmode, ivopts, tfms_count = _split_old_cipher_spec(spec)
        api = "%s(%s)" % (chainmode, cipher)
    if chainmode == "ecb":
        ivmode = None
    if ivmode is not None and ivmode not in _DM_CRYPT_IV_MODES:
        raise ValueError("Invalid IV mode: %r" % ivmode)
    if ivmode == "essiv":
        if ivopts is None:
            raise ValueError("Digest algorithm missing for ESSIV mode")
        api = "essiv(%s,%s)" % (api, ivopts)
    if len(api) >= CRYPTO_MAX_ALG_NAME:
        raise ValueError("Cannot allocate cipher string (%d chars)" % len(api))
    return CipherSpec(cipher=cipher, chainmode=chainmode, ivmode=ivmode, ivopts=ivopts,
                      key_parts=_key_parts_for_ivmode(ivmode, tfms_count, key_size),
                      crypto_api_name=api)
