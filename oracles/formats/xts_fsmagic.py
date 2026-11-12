"""dm-crypt / VeraCrypt data-area oracle: a volume key is proven by the filesystem it decrypts.

The candidate is a dm-crypt volume key as the kernel holds it (``key1 || key2`` for XTS).
The evidence is the first bytes of the volume's ENCRYPTED data area (e.g. recovered from
the page cache of a loop-mounted container file). Decrypting them with the right key gives
a well-formed filesystem head; ``fsmagic.best_match`` scores that structure in bits (the
bits a random plaintext would have to hit by chance) and ``min_bits`` (default 64) is the
proof threshold. No header, password or KDF is involved, which is why this is the proof for
VeraCrypt: its header is encrypted under the password-derived key, so it cannot prove a
master key recovered from memory, while its data area can.

Verdicts:

* ``proven``   -- a filesystem / volume head with at least ``min_bits`` bits decrypts out.
* ``rejected`` -- the key is the wrong length for the cipher spec, or (ONLY when the sample
  names the filesystem) the decrypted probe blocks show none of its magics and look random,
  or no head is found and every written unit decrypts to >= 7.0 bits/byte of entropy.
* ``error``    -- no verdict: ``no-written-units`` (every sampled unit is all-zero
  ciphertext, i.e. never written or not resident), ``plaintext-structured-unrecognized``
  (some unit decrypts to structured bytes yet no known head: a filesystem this module does
  not know, or a wrong ``fs`` / geometry), or ``unrecognized-fs-unknown`` (random-looking
  plaintext, but with ``fs="unknown"`` the sample cannot say that the key is wrong).

All-zero ciphertext units never count either way.

Geometry (as in the dm table ``<start> <len> crypt <spec> <key> <iv_offset> <dev>
<offset> [sector_size:N] [iv_large_sectors]``): ``spec`` is one of ``aes-xts-plain64``,
``aes-xts-plain``, ``aes-cbc-plain64``, ``aes-cbc-plain``, ``aes-cbc-essiv:sha256``;
``sector_size`` the encryption unit (512..4096); ``iv_offset`` the table's IV offset in
512-byte sectors; ``iv_large`` the ``iv_large_sectors`` option; ``data_offset`` the byte
offset of the data area in the container (informational, and the base of ``veracrypt``).
Aliases: ``iv_mode`` = ``plain64`` | ``plain`` | ``essiv-sha256`` | ``veracrypt`` sets the
IV part of ``spec`` (``veracrypt`` = ``aes-xts-plain64`` with ``iv_offset = data_offset /
512``, ``data_offset`` defaulting to 131072, i.e. ``iv_offset`` 256, as cryptsetup's tcrypt
mapping does); ``first_unit`` is the IV sector of the data area's first unit (it sets
``iv_offset``: equal to it, or shifted left by ``log2(sector_size / 512)`` with
``iv_large``).

Sample (``make_sample``, at most 8 KiB)::

    b"MDXF" || u8 version (1) || BE16 len(header) || header JSON || payload
    header  = {"spec", "sector_size", "iv_offset", "iv_large", "data_offset", "fs",
               "extents": [[rel_offset, length], ...]}   (+ optional "key_bytes")
    payload = the ciphertext of every extent, concatenated in order

``rel_offset`` counts from the start of the data area (= the decrypted device offset that
``fsmagic`` reads) and is a multiple of ``sector_size``; a length is a multiple of 16 (a
shorter last unit is a prefix of that unit, which XTS and CBC decrypt alike). The default
extent is ``[0, 4096)``; ``btrfs_unit=True`` (implied by ``fs="btrfs"``) adds the 512 bytes
at 64 KiB holding the btrfs magic. The sample holds ciphertext only.

The crypto lives in the stdlib-only primitives ``aes`` (``dm_decrypt_unit``,
``dm_decrypt_block``, ``dm_iv_sector``) and ``fsmagic`` (``classify``, ``best_match``,
``PROBES``), bound by the loader (see ``REQUIRES_PRIMITIVES``); ``aes`` uses
``cryptography`` when importable and pure Python otherwise. Without them ``verify`` returns
an ``error`` verdict.

AES-192-XTS (48-byte keys) is a valid dm-crypt configuration listed in
``CANDIDATE_LENGTHS``, but the ``aes`` primitive only does XTS with 32/64-byte keys, so a
built oracle never accepts 48 bytes.
"""
import collections
import json
import math
import re
import struct

KIND = "xts-fsmagic"
CANDIDATE_LENGTHS = (16, 24, 32, 48, 64)
# Measured per verify() of a WRONG candidate, best of 3 x 3000, CPython 3.11.9 /
# cryptography 46.0.3, Apple M1 Max, ext4 sample with 4096-byte units: 19.5 us when the sample
# names its filesystem (the probe rejects after one short decryption), 172 us with
# fs="unknown" (every candidate is fully decrypted and its entropy measured).
# oracle.cost_us reports the one that applies.
COST_US = 20
UNKNOWN_FS_COST_US = 180
SAMPLE_KIND = ("the first ciphertext bytes of a dm-crypt / VeraCrypt data area (default 4 KiB) "
               "+ its dm geometry (spec, sector_size, iv_offset, iv_large) and filesystem")
REQUIRES_PRIMITIVES = ("aes", "fsmagic")

SAMPLE_MAGIC = b"MDXF"
SAMPLE_VERSION = 1
SAMPLE_MAX_BYTES = 8192
SAMPLE_PARSE_MAX_BYTES = 1 << 20
DEFAULT_EXTENT_BYTES = 4096
BTRFS_UNIT_OFFSET = 0x10000
BTRFS_UNIT_BYTES = 512
VERACRYPT_DATA_OFFSET = 131072
DM_SECTOR_BYTES = 512
AES_BLOCK = 16
DEFAULT_MIN_BITS = 64
RANDOM_ENTROPY_BITS = 7.0
MIN_ENTROPY_SAMPLE = 256  # fewer plaintext bytes say nothing reliable about entropy
RANDOM_PROBE_DISTINCT = 14  # 16 random bytes have >= 14 distinct values ~99% of the time

SPECS = ("aes-xts-plain64", "aes-xts-plain", "aes-cbc-plain64", "aes-cbc-plain",
         "aes-cbc-essiv:sha256")
IV_MODES = ("plain64", "plain", "essiv-sha256", "veracrypt")
FS_NAMES = ("ext4", "xfs", "vfat", "ntfs", "lvm2", "swap", "gpt", "btrfs", "unknown")
FS_ALIASES = {"ext2": "ext4", "ext3": "ext4", "fat": "vfat", "fat12": "vfat", "fat16": "vfat",
              "fat32": "vfat", "msdos": "vfat", "exfat": "unknown", "": "unknown",
              "auto": "unknown", "none": "unknown"}
KEY_LENGTHS = {"xts": (32, 64), "cbc": (16, 24, 32)}
# LVM2 may put its label in any of sectors 0..3; fsmagic.PROBES lists sector 1 only.
_EXTRA_PROBES = (("lvm2", 0x000, b"LABELONE"), ("lvm2", 0x400, b"LABELONE"),
                 ("lvm2", 0x600, b"LABELONE"))
_SPEC_RE = re.compile(r"^aes-(xts|cbc)-(plain64|plain|essiv:sha256)$")


# --------------------------------------------------------------------------
# Geometry
# --------------------------------------------------------------------------

def _as_int(value, name, low=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < low:
        raise ValueError("%s must be an integer >= %d, not %r" % (name, low, value))
    return value


def canonical_fs(fs):
    """``"ext3"`` -> ``"ext4"``, ``None`` -> ``"unknown"``; ValueError for anything unknown."""
    name = "unknown" if fs is None else str(fs).strip().lower()
    name = FS_ALIASES.get(name, name)
    if name not in FS_NAMES:
        raise ValueError("unknown filesystem %r; known: %s" % (fs, ", ".join(FS_NAMES)))
    return name


def canonical_spec(spec, iv_mode=None):
    """The dm cipher spec, with ``iv_mode`` (an alias) replacing its IV part."""
    spec = str(spec or "aes-xts-plain64").strip().lower()
    match = _SPEC_RE.match(spec)
    if match is None or spec not in SPECS:  # aes-xts-essiv is not a dm-crypt mode we decrypt
        raise ValueError("unsupported dm-crypt spec %r; supported: %s" % (spec, ", ".join(SPECS)))
    chain = match.group(1)
    if iv_mode is None:
        return spec
    mode = str(iv_mode).strip().lower()
    if mode not in IV_MODES:
        raise ValueError("iv_mode must be one of %s, not %r" % (", ".join(IV_MODES), iv_mode))
    if mode == "essiv-sha256":
        return "aes-cbc-essiv:sha256"
    if mode == "veracrypt":
        if chain != "xts":
            raise ValueError("iv_mode veracrypt is aes-xts-plain64, not %s" % spec)
        return "aes-xts-plain64"
    return "aes-%s-%s" % (chain, mode)


def _unit_shift(sector_size):
    return (sector_size // DM_SECTOR_BYTES).bit_length() - 1


def resolve_geometry(spec="aes-xts-plain64", sector_size=512, iv_offset=0, iv_large=False,
                     data_offset=0, iv_mode=None, first_unit=None, key_bytes=None):
    """Canonical geometry dict; the ``iv_mode`` / ``first_unit`` aliases are folded in."""
    sector_size = _as_int(sector_size, "sector_size", DM_SECTOR_BYTES)
    if sector_size > 4096 or sector_size & (sector_size - 1):
        raise ValueError("sector_size must be a power of two in 512..4096, not %d" % sector_size)
    iv_offset = _as_int(iv_offset, "iv_offset")
    data_offset = _as_int(data_offset, "data_offset")
    if not isinstance(iv_large, bool):
        raise ValueError("iv_large must be a bool, not %r" % (iv_large,))
    spec = canonical_spec(spec, iv_mode)
    if iv_mode is not None and str(iv_mode).strip().lower() == "veracrypt":
        data_offset = data_offset or VERACRYPT_DATA_OFFSET
        iv_offset = _agree(iv_offset, data_offset // DM_SECTOR_BYTES, "iv_offset (veracrypt)")
    if first_unit is not None:
        unit_iv = _as_int(first_unit, "first_unit")
        iv_offset = _agree(iv_offset, unit_iv << _unit_shift(sector_size) if iv_large
                           else unit_iv, "iv_offset (first_unit)")
    geometry = {"spec": spec, "sector_size": sector_size, "iv_offset": iv_offset,
                "iv_large": iv_large, "data_offset": data_offset}
    if key_bytes is not None:
        allowed = KEY_LENGTHS[spec.split("-")[1]]
        if _as_int(key_bytes, "key_bytes", 1) not in allowed:
            raise ValueError("key_bytes %d does not fit %s (%s)" % (key_bytes, spec, allowed))
        geometry["key_bytes"] = key_bytes
    return geometry


def _agree(given, derived, name):
    if given not in (0, derived):
        raise ValueError("%s: %d contradicts the derived %d" % (name, given, derived))
    return derived


def key_lengths(geometry):
    """Exact candidate lengths for this geometry."""
    if geometry.get("key_bytes"):
        return (geometry["key_bytes"],)
    return KEY_LENGTHS[geometry["spec"].split("-")[1]]


# --------------------------------------------------------------------------
# Sample blob
# --------------------------------------------------------------------------

def make_sample(data_area, spec="aes-xts-plain64", sector_size=512, iv_offset=0,
                iv_large=False, data_offset=0, fs="unknown", btrfs_unit=False,
                iv_mode=None, first_unit=None, key_bytes=None):
    """Pack the first ciphertext bytes of a data area plus its geometry (<= 8 KiB).

    ``data_area`` starts at the first byte of the encrypted data area (the container offset
    ``data_offset``). The first 4 KiB are kept, plus 512 bytes at 64 KiB with ``btrfs_unit``.
    """
    if not isinstance(data_area, (bytes, bytearray, memoryview)):
        raise ValueError("data_area must be bytes")
    data_area = bytes(data_area)
    geometry = resolve_geometry(spec, sector_size, iv_offset, iv_large, data_offset,
                                iv_mode, first_unit, key_bytes)
    fs = canonical_fs(fs)
    head = min(DEFAULT_EXTENT_BYTES, len(data_area)) // AES_BLOCK * AES_BLOCK
    if not head:
        raise ValueError("data_area holds no whole 16-byte block")
    extents = [(0, data_area[:head])]
    if btrfs_unit or fs == "btrfs":
        end = BTRFS_UNIT_OFFSET + BTRFS_UNIT_BYTES
        if len(data_area) < end:
            raise ValueError("btrfs_unit needs %d bytes of data_area, got %d" % (end, len(data_area)))
        extents.append((BTRFS_UNIT_OFFSET, data_area[BTRFS_UNIT_OFFSET:end]))
    header = dict(geometry, fs=fs, extents=[[rel, len(buf)] for rel, buf in extents])
    head_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    blob = (SAMPLE_MAGIC + struct.pack(">BH", SAMPLE_VERSION, len(head_json)) + head_json
            + b"".join(buf for _, buf in extents))
    if len(blob) > SAMPLE_MAX_BYTES:
        raise ValueError("sample is %d bytes, over the %d cap" % (len(blob), SAMPLE_MAX_BYTES))
    return blob


def parse_sample(sample):
    """``(header dict, [(rel_offset, ciphertext), ...])`` of a make_sample() blob."""
    if not isinstance(sample, (bytes, bytearray, memoryview)):
        raise ValueError("sample must be bytes")
    sample = bytes(sample)
    start = len(SAMPLE_MAGIC) + 3
    if not sample.startswith(SAMPLE_MAGIC) or len(sample) < start:
        raise ValueError("not an xts-fsmagic sample (bad magic or too short)")
    if len(sample) > SAMPLE_PARSE_MAX_BYTES:
        raise ValueError("xts-fsmagic sample of %d bytes is implausibly large" % len(sample))
    version, head_len = struct.unpack_from(">BH", sample, len(SAMPLE_MAGIC))
    if version != SAMPLE_VERSION:
        raise ValueError("xts-fsmagic sample version %d is not %d" % (version, SAMPLE_VERSION))
    header = json.loads(sample[start:start + head_len].decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError("xts-fsmagic sample header is not a JSON object")
    return header, _split_extents(header, sample[start + head_len:])


def _split_extents(header, payload):
    raw = header.get("extents")
    if not isinstance(raw, list) or not raw:
        raise ValueError("xts-fsmagic sample header has no extents")
    sector_size = header.get("sector_size", 512)
    extents, at = [], 0
    for item in raw:
        if not (isinstance(item, list) and len(item) == 2):
            raise ValueError("extent %r is not [rel_offset, length]" % (item,))
        rel, length = _as_int(item[0], "extent offset"), _as_int(item[1], "extent length", 1)
        if isinstance(sector_size, int) and sector_size > 0 and rel % sector_size:
            raise ValueError("extent offset %d is not aligned to sector_size %d" % (rel, sector_size))
        if length % AES_BLOCK:
            raise ValueError("extent length %d is not a multiple of 16" % length)
        extents.append((rel, payload[at:at + length]))
        at += length
    if at != len(payload):
        raise ValueError("extents cover %d bytes but the payload holds %d" % (at, len(payload)))
    return extents


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------

_GEOMETRY_KEYS = ("spec", "sector_size", "iv_offset", "iv_large", "data_offset", "key_bytes")


def build_oracle(params, sample):
    """Build a verifier.

    ``params`` (all optional) override the sample: ``spec``, ``sector_size``, ``iv_offset``,
    ``iv_large``, ``data_offset``, ``key_bytes``, ``fs``, and the aliases ``iv_mode`` and
    ``first_unit``; plus ``min_bits`` (default 64) and ``entropy_min`` (default 7.0).
    """
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    header, extents = parse_sample(sample)
    merged = {k: header.get(k) for k in _GEOMETRY_KEYS if header.get(k) is not None}
    merged.update({k: params[k] for k in _GEOMETRY_KEYS if params.get(k) is not None})
    geometry = resolve_geometry(iv_mode=params.get("iv_mode"),
                                first_unit=params.get("first_unit"), **merged)
    fs = canonical_fs(params.get("fs", header.get("fs")))
    min_bits = _as_int(params.get("min_bits", DEFAULT_MIN_BITS), "min_bits", 1)
    entropy_min = float(params.get("entropy_min", RANDOM_ENTROPY_BITS))
    return XtsFsmagicOracle(geometry, fs, extents, min_bits, entropy_min)


def _primitives():
    return globals().get("aes"), globals().get("fsmagic")


def shannon_entropy(data):
    """Bits per byte of ``data`` (0.0 for empty input)."""
    if not data:
        return 0.0
    total = float(len(data))
    return -sum(n / total * math.log2(n / total) for n in collections.Counter(data).values())


class XtsFsmagicOracle:
    """Verifies a dm-crypt volume key against the ciphertext head of its data area."""

    unique = True

    def __init__(self, geometry, fs, extents, min_bits, entropy_min):
        self.geometry, self.fs = geometry, fs
        self.spec, self.sector_size = geometry["spec"], geometry["sector_size"]
        self.candidate_lengths = key_lengths(geometry)
        self.min_bits, self.entropy_min = min_bits, entropy_min
        self.cost_us = COST_US if fs != "unknown" else UNKNOWN_FS_COST_US
        self.units = [(rel + at, buf[at:at + self.sector_size])
                      for rel, buf in extents for at in range(0, len(buf), self.sector_size)]
        self.written = [(off, unit) for off, unit in self.units if any(unit)]
        self.zero_units = len(self.units) - len(self.written)
        aes = globals().get("aes")
        self.backend = aes.backend() if aes is not None else None
        self._probes = None

    # -- cheap stage --------------------------------------------------------

    def prefilter(self, candidate):
        """A rejection reason (wrong length; probes of the named fs decrypt to noise) or None."""
        try:
            reason = self._length_reason(candidate)
            return reason or self._probe_reason(bytes(candidate))
        except Exception:  # a prefilter rejects nothing it cannot judge
            return None

    def _length_reason(self, candidate):
        if len(candidate) not in self.candidate_lengths:
            return "candidate is %d bytes; %s takes %s" % (
                len(candidate), self.spec, list(self.candidate_lengths))
        return None

    def _iv_sector(self, aes, rel_offset):
        g = self.geometry
        return aes.dm_iv_sector(rel_offset // DM_SECTOR_BYTES, g["iv_offset"], g["sector_size"],
                                g["iv_large"])

    def _probe_plan(self, aes, fsmagic):
        """``[(magic offset, magic, unit offset, unit, iv sector)]`` for the named fs's probes."""
        if self._probes is None:
            plan = []
            for name, offset, magic in tuple(fsmagic.PROBES) + _EXTRA_PROBES:
                if name != self.fs:
                    continue
                for unit_off, unit in self.written:
                    if unit_off <= offset and offset + len(magic) <= unit_off + len(unit):
                        plan.append((offset, magic, unit_off, unit, self._iv_sector(aes, unit_off)))
            self._probes = plan
        return self._probes

    def _probe_reason(self, key):
        """Rejection reason when the named fs's magics are absent and the blocks look random."""
        aes, fsmagic = _primitives()
        if self.fs == "unknown" or aes is None or fsmagic is None:
            return None
        plan = self._probe_plan(aes, fsmagic)
        if not plan:
            return None
        for offset, magic, unit_off, unit, iv in plan:
            plain = self._decrypt_span(aes, key, unit, iv, offset - unit_off, len(magic))
            if plain[0] == magic or len(set(plain[1])) < RANDOM_PROBE_DISTINCT:
                return None
        return "no %s magic at %s; probe blocks decrypt to random bytes" % (
            self.fs, ", ".join("%#x" % p[0] for p in plan))

    def _decrypt_span(self, aes, key, unit, iv, at, length):
        """``(bytes at [at, at+length) of the plaintext unit, the first decrypted block)``.

        Pure Python decrypts only the 1-2 blocks needed (``dm_decrypt_block``); with an
        accelerated ``aes`` one library call over the unit's prefix is cheaper than the two
        single-block calls (measured 14 vs 27 us for the ext4 probe at 0x438).
        """
        first, last = at // AES_BLOCK, (at + length - 1) // AES_BLOCK
        if self.backend == "cryptography":
            prefix = aes.dm_decrypt_unit(key, self.spec, iv, unit[:(last + 1) * AES_BLOCK])
            blocks = prefix[first * AES_BLOCK:]
        else:
            blocks = b"".join(aes.dm_decrypt_block(key, self.spec, iv, unit, i)
                              for i in range(first, last + 1))
        start = at - first * AES_BLOCK
        return blocks[start:start + length], blocks[:AES_BLOCK]

    # -- full verification -------------------------------------------------

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises. ``ctx`` is accepted and unused."""
        try:
            return self._verify(candidate)
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", "verify failed: %r" % (exc,))

    def _verify(self, candidate):
        if not isinstance(candidate, (bytes, bytearray, memoryview)):
            return self._verdict("error", "candidate must be bytes, not %s" % type(candidate).__name__)
        key = bytes(candidate)
        reason = self._length_reason(key)
        if reason:
            return self._verdict("rejected", reason)
        aes, fsmagic = _primitives()
        if aes is None or fsmagic is None:
            return self._verdict("error", "primitives aes and fsmagic are not loaded")
        if not self.written:
            return self._verdict("error", "no-written-units: all %d sampled units are zero "
                                 "ciphertext" % len(self.units))
        reason = self._probe_reason(key)
        if reason:
            return self._verdict("rejected", "probe: " + reason)
        return self._judge_plaintext(fsmagic, self._decrypt_written(aes, key))

    def _decrypt_written(self, aes, key):
        """``[(rel offset, plaintext unit)]`` for every non-zero ciphertext unit."""
        return [(off, aes.dm_decrypt_unit(key, self.spec, self._iv_sector(aes, off), unit))
                for off, unit in self.written]

    def _judge_plaintext(self, fsmagic, plain_units):
        extents = _merge_contiguous(plain_units)
        match = fsmagic.best_match(extents, self.min_bits)
        if match is not None:
            return self._verdict("proven", "%s head, %d bits: %s" % (match.fs, match.bits, match.detail),
                                 self._evidence(match))
        found = fsmagic.classify(extents)
        entropies = [shannon_entropy(unit) for _, unit in plain_units]
        low = min(entropies)
        random_units = all(len(unit) >= MIN_ENTROPY_SAMPLE and h >= self.entropy_min
                           for (_, unit), h in zip(plain_units, entropies))
        if self.fs != "unknown" and not found and random_units:
            return self._verdict("rejected", "no %s head; all %d written units decrypt to random "
                                 "bytes (min %.2f bits/byte)" % (self.fs, len(plain_units), low))
        if not random_units:
            return self._verdict("error", "plaintext-structured-unrecognized: min entropy %.2f "
                                 "bits/byte, best head %s" % (low, _describe(found)))
        return self._verdict("error", "unrecognized-fs-unknown: no head and random-looking "
                             "plaintext (min %.2f bits/byte); name the fs to allow a rejection" % low)

    def _evidence(self, match):
        evidence = dict(self.geometry, fs=match.fs, bits=match.bits, match=match.detail,
                        expected_fs=self.fs, units=len(self.written), zero_units=self.zero_units,
                        backend=self.backend)
        evidence["fs_mismatch"] = self.fs not in ("unknown", match.fs)
        return evidence

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}


def _merge_contiguous(units):
    """``{start: bytes}`` with touching units joined, so fsmagic reads fields across units."""
    merged = {}
    run_start, run = None, []
    for off, plain in sorted(units):
        if run_start is not None and off == run_start + sum(len(p) for p in run):
            run.append(plain)
            continue
        if run_start is not None:
            merged[run_start] = b"".join(run)
        run_start, run = off, [plain]
    if run_start is not None:
        merged[run_start] = b"".join(run)
    return merged


def _describe(found):
    if not found:
        return "none"
    return "%s (%d bits)" % (found[0].fs, found[0].bits)
