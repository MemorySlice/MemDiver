"""Generic AEAD oracle: a key is proven by authenticating one sealed message.

The candidate is an AEAD key (or, with ``kdf="hkdf-sha256"``, the input keying material it
is derived from). The evidence is one sealed message the software wrote with that key:
nonce, associated data and ``ciphertext || tag``. A tag that verifies is the proof; a wrong
key passes a 16-byte tag with probability 2**-128.

Algorithms: ``aes-gcm`` (16/24/32-byte keys, any nonce length >= 8, tags of 12..16 bytes),
``chacha20-poly1305`` (32-byte key, 12-byte nonce, RFC 8439) and ``xchacha20-poly1305``
(32-byte key, 24-byte nonce, draft-irtf-cfrg-xchacha-03).

* ``proven``   -- the tag verifies under the (derived) key.
* ``rejected`` -- the tag does not verify, or the candidate has a length the algorithm
  never takes.
* ``error``    -- no verdict: no working crypto backend, malformed candidate.

What "proven" means: AES-GCM and (X)ChaCha20-Poly1305 are NOT key-committing, so "proven"
means "this key authenticates the sample". For a message that real software produced (not
one crafted to open under two chosen keys) that key is unique; an adversarially built
sample could authenticate under more than one.

Sample (``make_sample``, at most 8 KiB, so the sealed message must fit)::

    b"MDAE" || u8 version (1) || BE16 len(header) || header JSON || ciphertext || tag
    header = {"alg", "nonce": hex, "aad": hex, "tag_len"}

Parameters: ``kdf`` = ``none`` (default: the candidate IS the key) or ``hkdf-sha256``
(RFC 5869, ``salt`` hex default empty = 32 zero bytes, ``info`` text or ``hex:<hex>``,
``key_len`` the derived key length, default 32), as e.g. gocryptfs derives its content key.

Crypto backends, chosen once per built oracle (``oracle.backend``), each accepted only after
it opens a known answer and refuses a tampered copy:

1. ``cryptography`` (fastest);
2. ``pycryptodome`` (``Crypto.Cipher``; what ``volatility3[full]`` installs);
3. pure Python from the stdlib-only primitives ``aes`` (GCM) and ``chacha``
   ((X)ChaCha20-Poly1305), always available inside a generated plugin.

``MEMDIVER_PUREPY_CRYPTO=1`` forces the pure tier. The primitives are bound by the loader
(see ``REQUIRES_PRIMITIVES``) and cannot import each other, so this module carries its own
backend chain rather than layering on another format.
"""
import functools
import hashlib
import hmac
import json
import os
import struct

KIND = "aead-generic"
CANDIDATE_LENGTHS = (16, 24, 32)
# Measured per verify() of a WRONG candidate, best of 3 x 5000, CPython 3.11.9 /
# cryptography 46.0.3, Apple M1 Max, a 149-byte sealed gocryptfs block 0: aes-gcm 5.2 us,
# chacha20-poly1305 6.9 us, xchacha20-poly1305 14.7 us; hkdf-sha256 adds ~4 us. COST_US is
# the common aes-gcm case; a built oracle reports its own (oracle.cost_us).
COST_US = 8
COST_US_BY_ALG = {"aes-gcm": 6, "chacha20-poly1305": 7, "xchacha20-poly1305": 15}
HKDF_COST_US = 4
SAMPLE_KIND = "one AEAD-sealed message: algorithm, nonce, associated data, ciphertext || tag"
REQUIRES_PRIMITIVES = ("aes", "chacha")
BACKENDS = ("cryptography", "pycryptodome", "pure-python")
PURE_PYTHON_BACKEND = "pure-python"
PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"

SAMPLE_MAGIC = b"MDAE"
SAMPLE_VERSION = 1
SAMPLE_MAX_BYTES = 8192
FULL_TAG = 16
MIN_GCM_TAG = 12
MIN_GCM_NONCE = 8
ALGS = ("aes-gcm", "chacha20-poly1305", "xchacha20-poly1305")
ALG_ALIASES = {"aes-gcm": "aes-gcm", "gcm": "aes-gcm", "aesgcm": "aes-gcm",
               "aes-256-gcm": "aes-gcm", "aes-128-gcm": "aes-gcm", "aes-192-gcm": "aes-gcm",
               "chacha20-poly1305": "chacha20-poly1305", "chacha20poly1305": "chacha20-poly1305",
               "chacha": "chacha20-poly1305",
               "xchacha20-poly1305": "xchacha20-poly1305", "xchacha20poly1305": "xchacha20-poly1305",
               "xchacha": "xchacha20-poly1305"}
KEY_LENGTHS = {"aes-gcm": (16, 24, 32), "chacha20-poly1305": (32,), "xchacha20-poly1305": (32,)}
NONCE_LENGTHS = {"chacha20-poly1305": 12, "xchacha20-poly1305": 24}
KDFS = ("none", "hkdf-sha256")
_CHACHA_CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")

# Known answers for the backend self-test, sealed with cryptography 46.0.3 (xchacha with
# pycryptodome 3.23.0 and the chacha primitive, identical): key bytes(range(32)), nonce
# bytes(range(0x40, 0x40 + n)), AAD SELFTEST_AAD, plaintext SELFTEST_PLAINTEXT, 16-byte tag.
SELFTEST_PLAINTEXT = b"memdiver aead selftest"
SELFTEST_AAD = b"memdiver aad"
SELFTEST_SEALED = {
    ("aes-gcm", 12): "8fdcc3474f4ae271eda57257ff44603e15a02639c441d5912f7dc3d3883a8ac695d7010890fe",
    ("aes-gcm", 16): "58e77bbff5293279b96a0694fa4c95c7162c63b32c2a30ab14112e207660def98f4a11c00593",
    ("chacha20-poly1305", 12):
        "953111e51b3c8b7378ae9361dfcf1ea8d8aa177d378829209ac30ac01e4fd9f680b852673d7d",
    ("xchacha20-poly1305", 24):
        "b95c6814b9961c64af95e2dfcbbc16f7fedcd9a1602d2f6d74ad560f6fa603d4aa544184496f",
}


# --------------------------------------------------------------------------
# Sample blob
# --------------------------------------------------------------------------

def canonical_alg(name):
    key = str(name or "").strip().lower()
    if key not in ALG_ALIASES:
        raise ValueError("unknown AEAD %r; known: %s" % (name, ", ".join(ALGS)))
    return ALG_ALIASES[key]


def _check_geometry(alg, nonce, tag_len):
    if alg in NONCE_LENGTHS and len(nonce) != NONCE_LENGTHS[alg]:
        raise ValueError("%s takes a %d-byte nonce, not %d" % (alg, NONCE_LENGTHS[alg], len(nonce)))
    if alg == "aes-gcm" and len(nonce) < MIN_GCM_NONCE:
        raise ValueError("aes-gcm nonce must be at least %d bytes" % MIN_GCM_NONCE)
    low = MIN_GCM_TAG if alg == "aes-gcm" else FULL_TAG
    if isinstance(tag_len, bool) or not isinstance(tag_len, int) or not low <= tag_len <= FULL_TAG:
        raise ValueError("%s tag length must be %d..%d bytes, not %r" % (alg, low, FULL_TAG, tag_len))


def make_sample(alg, nonce, ciphertext, tag=None, aad=b"", tag_len=FULL_TAG):
    """Pack one sealed message. ``tag=None``: ``ciphertext`` ends with its ``tag_len`` tag."""
    alg = canonical_alg(alg)
    nonce, ciphertext, aad = bytes(nonce), bytes(ciphertext), bytes(aad)
    if tag is not None:
        tag_len = len(bytes(tag))
        ciphertext += bytes(tag)
    _check_geometry(alg, nonce, tag_len)
    if len(ciphertext) <= tag_len:
        raise ValueError("the sealed message holds no ciphertext beyond its %d-byte tag" % tag_len)
    head = json.dumps({"aad": aad.hex(), "alg": alg, "nonce": nonce.hex(), "tag_len": tag_len},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    blob = SAMPLE_MAGIC + struct.pack(">BH", SAMPLE_VERSION, len(head)) + head + ciphertext
    if len(blob) > SAMPLE_MAX_BYTES:
        raise ValueError("sample is %d bytes, over the %d cap" % (len(blob), SAMPLE_MAX_BYTES))
    return blob


def parse_sample(sample):
    """``{"alg", "nonce", "aad", "tag_len", "ciphertext", "tag"}`` of a make_sample() blob."""
    if not isinstance(sample, (bytes, bytearray, memoryview)):
        raise ValueError("sample must be bytes")
    sample = bytes(sample)
    start = len(SAMPLE_MAGIC) + 3
    if not sample.startswith(SAMPLE_MAGIC) or len(sample) < start:
        raise ValueError("not an aead-generic sample (bad magic or too short)")
    version, head_len = struct.unpack_from(">BH", sample, len(SAMPLE_MAGIC))
    if version != SAMPLE_VERSION:
        raise ValueError("aead-generic sample version %d is not %d" % (version, SAMPLE_VERSION))
    head = json.loads(sample[start:start + head_len].decode("utf-8"))
    if not isinstance(head, dict):
        raise ValueError("aead-generic sample header is not a JSON object")
    alg = canonical_alg(head.get("alg"))
    nonce, aad = bytes.fromhex(str(head.get("nonce", ""))), bytes.fromhex(str(head.get("aad", "")))
    tag_len = head.get("tag_len", FULL_TAG)
    _check_geometry(alg, nonce, tag_len)
    sealed = sample[start + head_len:]
    if len(sealed) <= tag_len:
        raise ValueError("sample holds no ciphertext beyond its %d-byte tag" % tag_len)
    return {"alg": alg, "nonce": nonce, "aad": aad, "tag_len": tag_len,
            "ciphertext": sealed[:-tag_len], "tag": sealed[-tag_len:]}


# --------------------------------------------------------------------------
# Key derivation (standard library only)
# --------------------------------------------------------------------------

def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 HKDF-SHA256; an empty ``salt`` means 32 zero bytes."""
    prk = hmac.digest(salt or b"\x00" * 32, ikm, "sha256")
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.digest(prk, block + info + bytes((counter,)), "sha256")
        okm += block
        counter += 1
    return okm[:length]


def _bytes_param(value, name):
    """``bytes`` from bytes, ``"hex:<hex>"`` or plain text (UTF-8)."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value[4:]) if value.startswith("hex:") else value.encode("utf-8")
    raise ValueError("%s must be bytes or text, not %r" % (name, value))


# --------------------------------------------------------------------------
# AEAD backends: cryptography -> pycryptodome -> pure Python
# --------------------------------------------------------------------------

class TagMismatch(Exception):
    """The AEAD tag did not verify (every opener raises this one)."""


def _purepy_forced():
    return os.environ.get(PUREPY_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def select_backend(alg, nonce_len):
    """``(name, open_message)`` of the first backend that passes the self-test.

    ``open_message(key, nonce, ciphertext, tag, aad)`` returns the plaintext or raises
    :class:`TagMismatch`. Raises RuntimeError naming why every backend is unusable.
    """
    loaders = [("cryptography", _load_cryptography), ("pycryptodome", _load_pycryptodome),
               (PURE_PYTHON_BACKEND, _load_pure)]
    if _purepy_forced():
        loaders = loaders[-1:]
    reasons = []
    for name, loader in loaders:
        try:
            opener = loader(alg)
            _self_test(alg, nonce_len, opener)
        except Exception as exc:  # RuntimeError names what is missing; else a broken install
            reasons.append(str(exc) if isinstance(exc, RuntimeError) else "%s: %r" % (name, exc))
            continue
        return name, opener
    raise RuntimeError("no AEAD backend for %s: %s" % (alg, "; ".join(reasons)))


def _self_test(alg, nonce_len, opener):
    """Raise unless ``opener`` opens the known answer and refuses it tampered."""
    # aes-gcm: the 96-bit nonce path, or the GHASH-derived J0 path for any other length.
    known = NONCE_LENGTHS.get(alg, 12 if nonce_len == 12 else 16)
    sealed = bytes.fromhex(SELFTEST_SEALED[(alg, known)])
    key, nonce = bytes(range(32)), bytes(range(0x40, 0x40 + known))
    ct, tag = sealed[:-FULL_TAG], sealed[-FULL_TAG:]
    if opener(key, nonce, ct, tag, SELFTEST_AAD) != SELFTEST_PLAINTEXT:
        raise ValueError("self-test: known answer opened to the wrong plaintext")
    try:
        opener(key, nonce, ct, tag[:-1] + bytes([tag[-1] ^ 1]), SELFTEST_AAD)
    except TagMismatch:
        return
    raise ValueError("self-test: a tampered known answer was accepted")


def _load_cryptography(alg):
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms, modes
    except ImportError:
        raise RuntimeError("backend 'cryptography' is not installed") from None
    if alg == "aes-gcm":
        raw = _cryptography_gcm(aead, Cipher, algorithms, modes)
    elif alg == "chacha20-poly1305":
        def raw(key, nonce, ct, tag, aad):
            return aead.ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad)
    else:
        def raw(key, nonce, ct, tag, aad):
            subkey = _hchacha20(Cipher, algorithms, key, nonce[:16])
            return aead.ChaCha20Poly1305(subkey).decrypt(b"\x00" * 4 + nonce[16:], ct + tag, aad)
    return _raising(raw, InvalidTag)


def _cryptography_gcm(aead, cipher_cls, algorithms, modes):
    def open_message(key, nonce, ct, tag, aad):
        if len(tag) == FULL_TAG:
            return aead.AESGCM(key).decrypt(nonce, ct + tag, aad)
        decryptor = cipher_cls(algorithms.AES(key),
                               modes.GCM(nonce, tag, min_tag_length=len(tag))).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ct) + decryptor.finalize()
    return open_message


def _raising(open_message, invalid_tag):
    """Wrap a library opener so that its tag exception becomes :class:`TagMismatch`."""
    def wrapped(key, nonce, ct, tag, aad):
        try:
            return open_message(key, nonce, ct, tag, aad)
        except invalid_tag:
            raise TagMismatch("tag mismatch") from None
    return wrapped


def _hchacha20(cipher_cls, algorithms, key, nonce16):
    """HChaCha20 (draft-irtf-cfrg-xchacha-03, 2.2) from one ChaCha20 block of ``cryptography``:
    the block is rounds(state) + state, so subtracting the input state leaves rounds(state)."""
    encryptor = cipher_cls(algorithms.ChaCha20(key, nonce16), mode=None).encryptor()
    out = struct.unpack("<16I", encryptor.update(bytes(64)))
    state = _CHACHA_CONSTANTS + struct.unpack("<8I", key) + struct.unpack("<4I", nonce16)
    words = [(out[i] - state[i]) & 0xFFFFFFFF for i in (0, 1, 2, 3, 12, 13, 14, 15)]
    return struct.pack("<8I", *words)


def _load_pycryptodome(alg):
    try:
        from Crypto.Cipher import AES, ChaCha20_Poly1305  # nosec B413 -- pycryptodome (maintained), guarded by the self-test
    except Exception:  # ImportError, or the unrelated legacy pycrypto without these ciphers
        raise RuntimeError("backend 'pycryptodome' is not installed") from None

    def open_message(key, nonce, ct, tag, aad):
        if alg == "aes-gcm":
            engine = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=len(tag))
        else:  # a 24-byte nonce selects XChaCha20-Poly1305
            engine = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        engine.update(aad)
        try:
            return engine.decrypt_and_verify(ct, tag)
        except ValueError:  # pycryptodome's "MAC check failed"
            raise TagMismatch("tag mismatch") from None
    return open_message


def _load_pure(alg):
    name = "aes" if alg == "aes-gcm" else "chacha"
    primitive = globals().get(name)
    if primitive is None:
        raise RuntimeError("pure-Python primitive %r is not loaded" % name)
    if alg == "aes-gcm":  # pure=True: aes.py would otherwise use cryptography when importable
        decrypt = functools.partial(primitive.gcm_decrypt, pure=True)
    elif alg == "chacha20-poly1305":
        decrypt = primitive.chacha20_poly1305_decrypt
    else:
        decrypt = primitive.xchacha20_poly1305_decrypt

    def open_message(key, nonce, ct, tag, aad):
        plaintext = decrypt(key, nonce, ct, tag, aad)
        if plaintext is None:
            raise TagMismatch("tag mismatch")
        return plaintext
    return open_message


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------

def build_oracle(params, sample):
    """Build a verifier; ``params``: ``kdf``, ``info``, ``salt``, ``key_len`` (see module doc)."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    return AeadOracle(params, parse_sample(sample))


class AeadOracle:
    """Verifies candidates against one sealed message."""

    unique = True

    def __init__(self, params, parsed):
        self.alg, self.nonce, self.aad = parsed["alg"], parsed["nonce"], parsed["aad"]
        self.ciphertext, self.tag = parsed["ciphertext"], parsed["tag"]
        self.kdf = str(params.get("kdf") or "none").strip().lower()
        if self.kdf not in KDFS:
            raise ValueError("kdf must be one of %s, not %r" % (", ".join(KDFS), params.get("kdf")))
        self.info = _bytes_param(params.get("info"), "info")
        self.salt = _bytes_param(params.get("salt"), "salt")
        self.key_len = params.get("key_len") or max(KEY_LENGTHS[self.alg])
        if self.kdf != "none" and self.key_len not in KEY_LENGTHS[self.alg]:
            raise ValueError("key_len %r does not fit %s %s" % (self.key_len, self.alg,
                                                               KEY_LENGTHS[self.alg]))
        self.candidate_lengths = KEY_LENGTHS[self.alg] if self.kdf == "none" else CANDIDATE_LENGTHS
        self.cost_us = COST_US_BY_ALG[self.alg] + (HKDF_COST_US if self.kdf != "none" else 0)
        try:
            self.backend, self._open = select_backend(self.alg, len(self.nonce))
            self.backend_error = None
        except RuntimeError as exc:
            self.backend, self._open, self.backend_error = None, None, str(exc)

    def prefilter(self, candidate):
        """A reason when the length cannot fit the algorithm / kdf, else None."""
        if len(candidate) not in self.candidate_lengths:
            return "candidate is %d bytes; %s (kdf %s) takes %s" % (
                len(candidate), self.alg, self.kdf, list(self.candidate_lengths))
        return None

    def key_for(self, candidate):
        if self.kdf == "none":
            return bytes(candidate)
        return hkdf_sha256(bytes(candidate), self.salt, self.info, self.key_len)

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises. ``ctx`` is accepted and unused."""
        try:
            return self._verify(candidate)
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", "verify failed: %r" % (exc,))

    def _verify(self, candidate):
        if not isinstance(candidate, (bytes, bytearray, memoryview)):
            return self._verdict("error", "candidate must be bytes, not %s" % type(candidate).__name__)
        reason = self.prefilter(candidate)
        if reason:
            return self._verdict("rejected", reason)
        if self._open is None:
            return self._verdict("error", self.backend_error)
        key = self.key_for(candidate)
        try:
            plaintext = self._open(key, self.nonce, self.ciphertext, self.tag, self.aad)
        except TagMismatch:
            return self._verdict("rejected", "%s tag mismatch" % self.alg)
        except Exception as exc:  # a backend failure is not a verdict on the key
            return self._verdict("error", "%s open failed: %r" % (self.alg, exc))
        return self._verdict("proven", "%s message authenticated" % self.alg,
                             self._evidence(key, plaintext))

    def _evidence(self, key, plaintext):
        evidence = {"alg": self.alg, "kdf": self.kdf, "backend": self.backend,
                    "tag_len": len(self.tag), "plaintext_len": len(plaintext),
                    "plaintext_sha256": hashlib.sha256(plaintext).hexdigest()}
        if self.kdf != "none":
            evidence["derived_key_hex"] = key.hex()
        return evidence

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
