"""LUKS1 / LUKS2 volume-key oracle: the header's PBKDF2 digest proves the dm-crypt key.

The candidate is a LUKS volume (master) key as dm-crypt holds it in kernel memory. LUKS
stores ``PBKDF2(hash, volume_key, salt, iterations)`` in its header (LUKS1 ``mkDigest``,
LUKS2 a ``pbkdf2`` entry of ``digests``); a candidate whose PBKDF2 equals it IS the volume
key (a wrong key matches with probability 2**-160 or less). No passphrase, keyslot or
ciphertext is involved.

* ``proven``   -- the PBKDF2 digest matches (``derived`` carries the dm geometry of the
  segments bound to that digest, ready for a ``dmsetup`` table).
* ``rejected`` -- the PBKDF2 digest differs, or the key has the wrong length.
* ``error``    -- no verdict: the iteration count exceeds ``max_iterations`` or the
  per-call budget (``refused``), or the header is malformed / names an unknown hash.

Sample (``make_sample``, at most 8 KiB)::

    LUKS1: the raw 592-byte ``luks_phdr`` (magic, cipher, mkDigest, salts, keyslot table;
           NOT the keyslot key material, so it is no passphrase-cracking target)
    LUKS2: compact JSON {"uuid", "digests", "segments", "keyslots": {id: {"key_size"}}}
           (the keyslot KDF parameters and areas are dropped for the same reason)

``build_oracle`` also accepts a raw LUKS2 header (binary header + JSON area); its checksum is
then checked. A compact JSON sample carries no checksum: whoever made it vouches for it.

Each candidate costs one PBKDF2 of the header's iteration count (LUKS1 typically ~10^5,
LUKS2 ~10^5..10^6): ``oracle.cost_us`` is the header's total iteration count times the
measured cost of one PBKDF2 iteration of its hash (``PBKDF2_US_PER_ITERATION``). ``oracle.prefilter`` rejects without any PBKDF2
what cannot be a cryptsetup-generated key: the wrong length, a run of 8 or more zero bytes,
equal XTS halves, or a byte entropy far below that of random bytes of that length
(thresholds measured on 400,000 random keys per length, all below the observed minimum).

The parser and the digest check live in the stdlib-only primitive ``luks``
(``vol3plugins/linux/secrets/luks.py``), bound by the loader (see ``REQUIRES_PRIMITIVES``).
PBKDF2 is ``hashlib.pbkdf2_hmac`` (standard library, C speed).
"""
import base64
import collections
import hashlib
import json
import math
import struct

KIND = "luks"
CANDIDATE_LENGTHS = (16, 24, 32, 48, 64)
# One PBKDF2-SHA256 of a typical LUKS1 mkDigest (~10^5 iterations) on CPython 3.11.9,
# Apple M1 Max: ~0.1-0.2 s. A built oracle reports the cost of ITS header (cost_us).
COST_US = 200000
SAMPLE_KIND = ("the LUKS header: LUKS1 raw 592-byte phdr, or a compact LUKS2 JSON document "
               "(digests, segments, keyslot key sizes)")
REQUIRES_PRIMITIVES = ("luks",)

LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS1_PHDR_BYTES = 592
LUKS2_BINARY_HEADER = 4096
SAMPLE_MAX_BYTES = 8192
# Microseconds per PBKDF2-HMAC iteration (hashlib, OpenSSL 3), best of 3 x 100,000
# iterations, CPython 3.11.9 on an Apple M1 Max. A reference table rather than a timing at
# build time: the paste-safe contract's module allow-list has no clock module. Unknown hashes
# are budgeted at the slowest listed one.
PBKDF2_US_PER_ITERATION = {"sha1": 0.39, "sha256": 0.17, "sha512": 0.35, "ripemd160": 1.17}
MAX_ZERO_RUN = 8
# Minimum byte entropy (bits/byte) of a plausible random key, per key length. Measured on
# 400,000 os-random keys per length (observed minimum): 16 -> 3.33, 24 -> 3.86, 32 -> 4.35,
# 48 -> 4.91, 64 -> 5.32. The thresholds sit below every observed value.
MIN_KEY_ENTROPY = {16: 3.2, 24: 3.7, 32: 4.3, 48: 4.6, 64: 5.0}
_ERROR_MARKERS = ("malformed", "unsupported hash", "not a LUKS header", "JSON area unavailable",
                  "no pbkdf2 digest", "not bytes-like", "empty key")


# --------------------------------------------------------------------------
# Sample blob
# --------------------------------------------------------------------------

def make_sample(header_bytes_or_doc):
    """Pack a LUKS header into a sample: LUKS1 raw phdr, LUKS2 compact JSON (<= 8 KiB).

    Accepts raw header bytes (LUKS1: at least 592 bytes; LUKS2: the binary header plus the
    whole JSON area), or a LUKS2 JSON document (dict, str or bytes starting with ``{``).
    """
    value = header_bytes_or_doc
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value)
        if value[:6] == LUKS_MAGIC and _version(value) == 1:
            if len(value) < LUKS1_PHDR_BYTES:
                raise ValueError("a LUKS1 phdr is %d bytes, got %d" % (LUKS1_PHDR_BYTES, len(value)))
            return value[:LUKS1_PHDR_BYTES]
        if value[:6] == LUKS_MAGIC:
            value = _luks2_json_area(value)
        elif value.lstrip()[:1] != b"{":
            raise ValueError("neither a LUKS header (magic) nor a LUKS2 JSON document")
    blob = json.dumps(compact_document(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(blob) > SAMPLE_MAX_BYTES:
        raise ValueError("sample is %d bytes, over the %d cap" % (len(blob), SAMPLE_MAX_BYTES))
    return blob


def _version(raw):
    return struct.unpack_from(">H", raw, 6)[0] if len(raw) >= 8 else None


def _luks2_json_area(raw):
    """The JSON text of a raw LUKS2 header (binary header + JSON area)."""
    if _version(raw) != 2 or len(raw) < LUKS2_BINARY_HEADER:
        raise ValueError("not a LUKS1 phdr or a whole LUKS2 header")
    hdr_size = struct.unpack_from(">Q", raw, 8)[0]
    if len(raw) < hdr_size:
        raise ValueError("LUKS2 header is %d bytes but only %d were given" % (hdr_size, len(raw)))
    return raw[LUKS2_BINARY_HEADER:hdr_size].split(b"\0", 1)[0]


def compact_document(document):
    """The parts of a LUKS2 JSON document that verification needs (no keyslot KDF data)."""
    if isinstance(document, (bytes, bytearray, str)):
        try:
            document = json.loads(document)
        except ValueError as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
            raise ValueError("not a LUKS2 JSON document: %s" % exc) from None
    if not isinstance(document, dict):
        raise ValueError("a LUKS2 JSON document is an object, not %s" % type(document).__name__)
    digests = document.get("digests")
    if not isinstance(digests, dict) or not digests:
        raise ValueError("the LUKS2 document has no digests")
    keyslots = document.get("keyslots") if isinstance(document.get("keyslots"), dict) else {}
    compact = {"digests": digests,
               "segments": document.get("segments") if isinstance(document.get("segments"), dict) else {},
               "keyslots": {str(k): {"key_size": v.get("key_size")} for k, v in keyslots.items()
                            if isinstance(v, dict) and "key_size" in v}}
    if isinstance(document.get("uuid"), str):
        compact["uuid"] = document["uuid"]
    return compact


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------

def build_oracle(params, sample):
    """Build a verifier.

    ``params`` (all optional): ``max_iterations`` (per digest, default the primitive's 20M),
    ``max_total_iterations`` (per verify call, default 40M) and ``uuid`` (for a raw LUKS2
    sample: the document's own is used otherwise).
    """
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    if not isinstance(sample, (bytes, bytearray, memoryview)) or not sample:
        raise ValueError("sample must be non-empty bytes")
    return LuksDigestOracle(params, bytes(sample))


def _primitive():
    return globals().get("luks")


def _parse(luks, sample):
    """``Luks1Header`` / ``Luks2Header`` of a sample; ValueError when it is not one."""
    if sample[:6] == LUKS_MAGIC:
        header = luks.parse_luks(sample)
        if _version(sample) == 2 and not (header.complete and header.checksum_ok):
            raise ValueError("raw LUKS2 sample lacks its JSON area or fails its checksum")
        return header
    if sample[:1] == b"{":
        return luks.luks2_from_document(sample)
    raise ValueError("not a luks sample (neither a LUKS phdr nor a LUKS2 JSON document)")


def _pbkdf2_entries(header):
    """``[(hash, salt, iterations, key lengths)]`` for every digest PBKDF2 will be run on."""
    if getattr(header, "version", 2) == 1:
        return [(header.hash_spec, header.mk_digest_salt, header.mk_digest_iter, {header.key_bytes})]
    entries = []
    for digest_id, digest in sorted(header.digests.items()):
        if not isinstance(digest, dict) or digest.get("type") != "pbkdf2":
            continue
        try:
            salt = base64.b64decode(digest["salt"], validate=True)
            base64.b64decode(digest["digest"], validate=True)
            iterations = int(digest["iterations"])
            hash_name = str(digest["hash"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("LUKS2 digest %s is malformed: %s" % (digest_id, exc)) from None
        lengths = set()
        for slot in digest.get("keyslots") or []:
            size = (header.keyslots.get(str(slot)) or {}).get("key_size")
            if isinstance(size, int) and size > 0:
                lengths.add(size)
        entries.append((hash_name, salt, iterations, lengths))
    if not entries:
        raise ValueError("the LUKS2 header has no pbkdf2 digest")
    return entries


def _check_entries(entries):
    for hash_name, _, iterations, _ in entries:
        if iterations <= 0:
            raise ValueError("PBKDF2 iteration count %d is not positive" % iterations)
        try:
            hashlib.new(hash_name)
        except (ValueError, TypeError):
            raise ValueError("unsupported LUKS hash %r" % (hash_name,)) from None


def pbkdf2_cost_us(hash_name, iterations):
    """Estimated microseconds for one PBKDF2 of ``iterations`` iterations of ``hash_name``."""
    per_iteration = PBKDF2_US_PER_ITERATION.get(str(hash_name).lower(),
                                                max(PBKDF2_US_PER_ITERATION.values()))
    return iterations * per_iteration


def shannon_entropy(data):
    """Bits per byte of ``data`` (0.0 for empty input)."""
    if not data:
        return 0.0
    total = float(len(data))
    return -sum(n / total * math.log2(n / total) for n in collections.Counter(data).values())


def _xts(header):
    if getattr(header, "version", 2) == 1:
        return header.cipher_mode.lower().startswith("xts")
    return any(isinstance(seg, dict) and "xts" in str(seg.get("encryption", "")).lower()
               for seg in header.segments.values())


class LuksDigestOracle:
    """Verifies a candidate volume key against the PBKDF2 digest(s) of one LUKS header."""

    unique = True

    def __init__(self, params, sample):
        self.max_iterations = params.get("max_iterations")
        self.max_total_iterations = params.get("max_total_iterations")
        self.header, self.entries, self.backend_error = None, [], None
        self.candidate_lengths, self.cost_us, self.xts, self.version = CANDIDATE_LENGTHS, COST_US, False, None
        luks = _primitive()
        if luks is None:  # a missing primitive is reported per verify, never raised here
            self.backend_error = "primitive luks is not loaded"
            return
        try:
            self.header = _parse(luks, sample)
        except luks.LuksParseError as exc:
            raise ValueError(str(exc)) from None
        self.entries = _pbkdf2_entries(self.header)
        _check_entries(self.entries)
        self.version = getattr(self.header, "version", 2)
        lengths = sorted(set().union(*(e[3] for e in self.entries)))
        self.candidate_lengths = tuple(lengths) or CANDIDATE_LENGTHS
        self.xts = _xts(self.header)
        self.cost_us = int(sum(pbkdf2_cost_us(e[0], e[2]) for e in self.entries)) + 1

    # -- cheap stage --------------------------------------------------------

    def prefilter(self, candidate):
        """A reason why ``candidate`` cannot be a cryptsetup key, or None (no PBKDF2 here)."""
        key = bytes(candidate)
        if len(key) not in self.candidate_lengths:
            return "candidate is %d bytes; the header wants %s" % (len(key), list(self.candidate_lengths))
        if bytes(MAX_ZERO_RUN) in key:
            return "a run of %d or more zero bytes" % MAX_ZERO_RUN
        if self.xts and key[:len(key) // 2] == key[len(key) // 2:]:
            return "equal XTS halves"
        floor = MIN_KEY_ENTROPY.get(len(key))
        entropy = shannon_entropy(key)
        if floor is not None and entropy < floor:
            return "entropy %.2f < %.1f bits/byte for a %d-byte key" % (entropy, floor, len(key))
        return None

    # -- verification --------------------------------------------------------

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises. ``ctx`` is accepted and unused."""
        try:
            return self._verify(candidate)
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", "verify failed: %r" % (exc,))

    def _limits(self, luks):
        limits = {"max_iterations": luks.DEFAULT_MAX_PBKDF2_ITERATIONS,
                  "max_total_iterations": luks.DEFAULT_MAX_TOTAL_ITERATIONS}
        if self.max_iterations is not None:
            limits["max_iterations"] = int(self.max_iterations)
        if self.max_total_iterations is not None:
            limits["max_total_iterations"] = int(self.max_total_iterations)
        return limits

    def _verify(self, candidate):
        if not isinstance(candidate, (bytes, bytearray, memoryview)):
            return self._verdict("error", "candidate must be bytes, not %s" % type(candidate).__name__)
        luks = _primitive()
        if luks is None or self.header is None:
            return self._verdict("error", self.backend_error or "primitive luks is not loaded")
        key = bytes(candidate)
        if len(key) not in self.candidate_lengths:
            return self._verdict("rejected", "candidate is %d bytes; the header wants %s"
                                 % (len(key), list(self.candidate_lengths)))
        verdict = luks.verify_volume_key(self.header, key, **self._limits(luks))
        if verdict.matched:
            return self._verdict("proven", "LUKS%d %s" % (self.version, verdict.detail),
                                 self._evidence(verdict))
        if getattr(verdict, "refused", False):
            return self._verdict("error", "refused: " + verdict.detail)
        if any(marker in verdict.detail for marker in _ERROR_MARKERS):
            return self._verdict("error", verdict.detail)
        return self._verdict("rejected", verdict.detail)

    def _evidence(self, verdict):
        return {"luks_version": self.version, "uuid": getattr(self.header, "uuid", ""),
                "digest_id": verdict.digest_id, "segments": verdict.segments,
                "iterations": [e[2] for e in self.entries], "hash": [e[0] for e in self.entries]}

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
