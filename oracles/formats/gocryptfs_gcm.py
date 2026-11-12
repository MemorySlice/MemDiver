"""gocryptfs content-file oracle (AES-GCM, XChaCha20-Poly1305, AES-SIV).

Proves a candidate gocryptfs key by AEAD-opening block 0 of one encrypted
content file of the vault. Nothing is mounted and neither the password nor
scrypt is involved: the candidate is the 32-byte master key as it sits in the
gocryptfs process (or, with ``candidate_is="content"``, the content key that
gocryptfs derives from it). A tag that verifies is the proof; a wrong key
fails the tag with probability 1 - 2**-128.

On-disk layout of an encrypted content file (gocryptfs on-disk format v2)::

    header  = version (2 bytes, big endian, == 2) || file_id (16 bytes)
    block_n = nonce || ciphertext (<= 4096 bytes) || tag (16 bytes)
    aad_n   = block_number (8 bytes, big endian) || file_id

AES-SIV seals as ``nonce || siv_tag || ciphertext`` and passes the nonce as
the last associated-data element (gocryptfs ``internal/siv_aead``).

Content key (gocryptfs ``internal/cryptocore``, source checked 2026-11-06)::

    HKDF flag set:  HKDF-SHA256(master, salt=None, info=<per cipher>, length)
    HKDF absent:    aes-gcm -> the master key itself; aes-siv -> SHA-512(master)
    xchacha:        HKDF is mandatory

The cipher follows gocryptfs.conf FeatureFlags: ``XChaCha20Poly1305`` ->
xchacha (24-byte nonce), ``AESSIV`` -> aes-siv (16-byte nonce), otherwise
aes-gcm with a 16-byte nonce when ``GCMIV128`` is set and the legacy 12-byte
nonce when it is not. Without a conf, pass ``cipher`` and, for legacy GCM,
``nonce_length=12`` (``hkdf=False`` with no conf also implies 12).

What "proven" means: AES-GCM and (X)ChaCha20-Poly1305 are NOT key-committing,
so "proven" means "this key authenticates the vault sample". For a vault that
real gocryptfs produced (not one crafted to open under two chosen keys) that
key is unique; an adversarially built sample could authenticate under more.

Crypto backends. HKDF runs on the standard library. The AEAD open is served by
the first usable of, chosen once per built oracle (``oracle.backend``):

1. ``cryptography`` (fastest);
2. ``pycryptodome`` (``Crypto.Cipher``; what ``volatility3[full]`` installs);
3. pure Python from the stdlib-only primitives ``aes`` (GCM, SIV) and
   ``chacha`` (XChaCha20-Poly1305), always available inside a generated plugin.

``MEMDIVER_PUREPY_CRYPTO=1`` forces the pure tier. Every tier is byte-identical
(differential tests in the repository); only speed differs.
"""
import functools
import hashlib
import hmac
import json
import os
import struct

KIND = "gocryptfs-gcm"
# 32: master keys and GCM/XChaCha content keys; 64: AES-SIV content keys. The
# exact length for one configuration is the oracle's ``candidate_lengths``.
CANDIDATE_LENGTHS = (32, 64)
# Measured per verify() of a WRONG candidate (the common case in a sweep),
# best of 3 x 20000, CPython 3.11.9 / cryptography 46.0.3 / arm64, on the
# 183/191-byte content files of the gocryptfs corpus: aes-gcm master 7.1 us,
# content 3.6 us; xchacha master 15.3 us, content 12.0 us. COST_US is the
# slowest supported master path (xchacha) rounded up, so budgets never undershoot.
#
# Per backend (2026-11-08, wrong key, master path, same 149-byte sealed block 0
# of the corpus files; aes-siv on a synthetic file of that size; CPython
# 3.11.9 on an Apple M1 Max; best of 3):
#
#   backend                  aes-gcm   xchacha   aes-siv
#   cryptography 46.0.3         5.8      12.6      14.9  us
#   pycryptodome 3.23.0        47.4      26.5     115.5  us
#   pure Python (primitives)  158.6     106.4     401.7  us
#
# COST_US stays the accelerator figure: it describes the backend MemDiver
# itself always has (cryptography is a dependency), and a module constant
# cannot know the host a plugin lands on. Budget a stock-Volatility run that
# logs the pure-Python warning with the last row (8-27x slower).
COST_US = 16
SAMPLE_KIND = "gocryptfs vault: one encrypted content file + gocryptfs.conf FeatureFlags"
# Pure-Python tier: aes.py (GCM, SIV) and chacha.py (XChaCha20-Poly1305) from
# vol3plugins/linux/secrets. The inline loader (and, in the repository, the
# memdiver.oracles registry) binds them as globals of this module after it loads.
REQUIRES_PRIMITIVES = ("aes", "chacha")
#: Backend names, fastest first; ``oracle.backend`` is one of them (or None).
BACKENDS = ("cryptography", "pycryptodome", "pure-python")
PURE_PYTHON_BACKEND = "pure-python"
PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"

MASTER_KEY_LEN = 32
FILE_HEADER_VERSION = 2
FILE_ID_LEN = 16
FILE_HEADER_LEN = 2 + FILE_ID_LEN
TAG_LEN = 16
BLOCK_PLAINTEXT_MAX = 4096
MIN_NONCE_LEN = 12
MAX_NONCE_LEN = 24
SAMPLE_MAGIC = b"MDGOCFS1"
SAMPLE_MAX_BYTES = 8192

# HKDF info strings, verbatim from gocryptfs internal/cryptocore/hkdf.go
# (https://github.com/rfjakob/gocryptfs/blob/master/internal/cryptocore/hkdf.go):
#   hkdfInfoGCMContent             = "AES-GCM file content encryption"
#   hkdfInfoSIVContent             = "AES-SIV file content encryption"
#   hkdfInfoXChaChaPoly1305Content = "XChaCha20-Poly1305 file content encryption"
# hkdfDerive() is hkdf.Key(sha256.New, masterkey, nil, info, outLen): no salt.
HKDF_INFO = {
    "aes-gcm": b"AES-GCM file content encryption",
    "aes-siv": b"AES-SIV file content encryption",
    "xchacha": b"XChaCha20-Poly1305 file content encryption",
}
CONTENT_KEY_LEN = {"aes-gcm": 32, "aes-siv": 64, "xchacha": 32}
CIPHER_ALIASES = {
    "aes": "aes-gcm",
    "gcm": "aes-gcm",
    "aes-gcm": "aes-gcm",
    "aes-256-gcm": "aes-gcm",
    "xchacha": "xchacha",
    "xchacha20-poly1305": "xchacha",
    "xchacha20poly1305": "xchacha",
    "siv": "aes-siv",
    "aes-siv": "aes-siv",
    "aessiv": "aes-siv",
}
VAULT_METADATA_FILES = ("gocryptfs.conf", "gocryptfs.diriv")
_CHACHA_CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")


# --------------------------------------------------------------------------
# Sample blob: MAGIC || BE16 len(meta) || meta JSON || file prefix
# --------------------------------------------------------------------------

def make_sample(ciphertext, conf=None, cipher=None):
    """Pack one encrypted content file (+ conf FeatureFlags) into a sample blob.

    ``ciphertext`` is the raw content of an encrypted file; only its header
    and the bytes block 0 can span are kept. ``conf`` is gocryptfs.conf as
    bytes, str or parsed dict; only FeatureFlags, Creator and Version are
    kept: EncryptedKey and the scrypt parameters are dropped on purpose, so a
    plugin carrying the sample is no offline password-cracking target.
    ``cipher`` is a hint used only when no conf is given.
    """
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise ValueError("ciphertext must be bytes")
    _check_file_header(ciphertext)
    meta = {"cipher": canonical_cipher(cipher) if cipher else None,
            "file_size": len(ciphertext)}
    meta.update(_conf_summary(conf))
    head = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    span = FILE_HEADER_LEN + MAX_NONCE_LEN + BLOCK_PLAINTEXT_MAX + TAG_LEN
    blob = SAMPLE_MAGIC + struct.pack(">H", len(head)) + head + bytes(ciphertext[:span])
    if len(blob) > SAMPLE_MAX_BYTES:
        raise ValueError(f"sample is {len(blob)} bytes, over the {SAMPLE_MAX_BYTES} cap")
    return blob


def parse_sample(sample):
    """Unpack a make_sample() blob into ``{"meta", "file_id", "body"}``."""
    if not isinstance(sample, (bytes, bytearray, memoryview)):
        raise ValueError("sample must be bytes")
    sample = bytes(sample)
    start = len(SAMPLE_MAGIC) + 2
    if not sample.startswith(SAMPLE_MAGIC) or len(sample) < start:
        raise ValueError("not a gocryptfs-gcm sample (bad magic or too short)")
    (head_len,) = struct.unpack_from(">H", sample, len(SAMPLE_MAGIC))
    meta = _check_meta(json.loads(sample[start:start + head_len].decode("utf-8")))
    prefix = sample[start + head_len:]
    _check_file_header(prefix)
    return {"meta": meta, "file_id": prefix[2:FILE_HEADER_LEN], "body": prefix[FILE_HEADER_LEN:]}


def _check_meta(meta):
    if not isinstance(meta, dict):
        raise ValueError("sample meta is not a JSON object")
    meta["feature_flags"] = _check_flags(meta.get("feature_flags"))
    if meta.get("cipher") is not None and not isinstance(meta["cipher"], str):
        raise ValueError("sample meta 'cipher' must be a string")
    size = meta.get("file_size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise ValueError("sample meta 'file_size' must be a non-negative integer")
    return meta


def _check_flags(flags):
    """FeatureFlags are None (unknown) or a list of strings; membership is exact."""
    if flags is None:
        return None
    if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
        raise ValueError(f"FeatureFlags must be a list of strings, not {flags!r}")
    return flags


def sample_from_vault(cipher_dir, cipher=None):
    """Build a sample from a vault's ciphertext directory (the one holding gocryptfs.conf)."""
    conf_path = os.path.join(cipher_dir, "gocryptfs.conf")
    conf = _read_file(conf_path) if os.path.isfile(conf_path) else None
    return make_sample(_read_file(find_content_file(cipher_dir)), conf, cipher=cipher)


def find_content_file(cipher_dir):
    """The smallest content file under ``cipher_dir`` whose block 0 is usable (not a hole)."""
    candidates = []
    for root, dirs, files in os.walk(cipher_dir):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            if _is_content_file(name, path):
                candidates.append((os.path.getsize(path), path))
    for _, path in sorted(candidates):
        if _block0_has_data(path):
            return path
    raise ValueError(f"no usable encrypted gocryptfs content file under {cipher_dir!r}")


def _block0_has_data(path):
    with open(path, "rb") as handle:
        handle.seek(FILE_HEADER_LEN)
        return bool(handle.read(MAX_NONCE_LEN + BLOCK_PLAINTEXT_MAX + TAG_LEN).strip(b"\x00"))


def _is_content_file(name, path):
    if name in VAULT_METADATA_FILES or os.path.islink(path):
        return False
    if name.startswith("gocryptfs.longname.") and name.endswith(".name"):
        return False
    if os.path.getsize(path) < FILE_HEADER_LEN + MIN_NONCE_LEN + TAG_LEN:
        return False
    with open(path, "rb") as handle:
        return handle.read(2) == struct.pack(">H", FILE_HEADER_VERSION)


def _read_file(path):
    with open(path, "rb") as handle:
        return handle.read()


def _check_file_header(data):
    if len(data) < FILE_HEADER_LEN + MIN_NONCE_LEN + TAG_LEN:
        raise ValueError(f"{len(data)} bytes is too short for a gocryptfs content file")
    (version,) = struct.unpack_from(">H", data, 0)
    if version != FILE_HEADER_VERSION:
        raise ValueError(f"file header version {version} is not gocryptfs v{FILE_HEADER_VERSION}")


def _conf_summary(conf):
    if conf is None:
        return {"feature_flags": None}
    if isinstance(conf, (bytes, bytearray)):
        conf = conf.decode("utf-8")
    if isinstance(conf, str):
        conf = json.loads(conf)
    if not isinstance(conf, dict):
        raise ValueError("gocryptfs.conf is not a JSON object")
    return {"feature_flags": _check_flags(conf.get("FeatureFlags") or []),
            "creator": conf.get("Creator"),
            "conf_version": conf.get("Version")}


# --------------------------------------------------------------------------
# Parameters
# --------------------------------------------------------------------------

def canonical_cipher(name):
    """Map a cipher name or alias ("aes", "xchacha", ...) to aes-gcm|xchacha|aes-siv."""
    key = name.strip().lower() if isinstance(name, str) else None
    if key not in CIPHER_ALIASES:
        raise ValueError(f"unknown gocryptfs cipher {name!r}; known: {sorted(CIPHER_ALIASES)}")
    return CIPHER_ALIASES[key]


def cipher_from_flags(flags):
    """The content cipher gocryptfs uses for these gocryptfs.conf FeatureFlags."""
    if "XChaCha20Poly1305" in flags:
        return "xchacha"
    if "AESSIV" in flags:
        return "aes-siv"
    return "aes-gcm"


def resolve_cipher(requested, hinted, flags):
    """Explicit parameter, else conf FeatureFlags, else the make_sample() hint."""
    if requested not in (None, "", "auto"):
        cipher = canonical_cipher(requested)
        if flags is not None and cipher != cipher_from_flags(flags):
            raise ValueError(f"cipher {requested!r} contradicts gocryptfs.conf FeatureFlags "
                             f"{flags} (which say {cipher_from_flags(flags)})")
        return cipher
    if flags is not None:
        return cipher_from_flags(flags)
    if hinted:
        return canonical_cipher(hinted)
    raise ValueError("cipher unknown: the sample carries no gocryptfs.conf FeatureFlags; "
                     "pass params['cipher'] (aes-gcm, xchacha or aes-siv)")


def nonce_length(cipher, flags, requested=None, hkdf=True):
    """Per-block nonce length: 24 (xchacha), 16 (aes-siv, GCMIV128) or 12 (legacy GCM).

    For aes-gcm without conf flags, ``requested`` (12 or 16) decides; failing
    that, ``hkdf=False`` implies a pre-1.3 vault and so the legacy 12 bytes.
    """
    if requested is not None and (isinstance(requested, bool) or requested not in (12, 16)):
        raise ValueError(f"nonce_length must be 12 or 16, not {requested!r}")
    if cipher == "xchacha":
        natural = 24
    elif cipher == "aes-siv" or (flags is not None and "GCMIV128" in flags):
        natural = 16
    elif flags is not None:
        natural = 12
    else:
        return requested or (16 if hkdf else 12)
    if requested is not None and requested != natural:
        raise ValueError(f"nonce_length {requested} contradicts {cipher} / FeatureFlags ({natural})")
    return natural


def _resolve_hkdf(requested, flags, cipher):
    if requested is None:
        hkdf = True if flags is None else "HKDF" in flags
    elif isinstance(requested, bool):
        hkdf = requested
    else:
        raise ValueError(f"hkdf must be True, False or None, not {requested!r}")
    if cipher == "xchacha" and not hkdf:
        raise ValueError("gocryptfs never uses XChaCha20-Poly1305 without HKDF")
    return hkdf


def _resolve_candidate_is(requested):
    candidate_is = "master" if requested is None else requested
    if candidate_is not in ("master", "content"):
        raise ValueError(f"candidate_is must be 'master' or 'content', not {requested!r}")
    return candidate_is


# --------------------------------------------------------------------------
# Key derivation (standard library only)
# --------------------------------------------------------------------------

def hkdf_sha256(ikm, info, length):
    """RFC 5869 HKDF-SHA256 with an empty salt (= 32 zero bytes), as gocryptfs calls it."""
    prk = hmac.digest(b"\x00" * 32, ikm, "sha256")
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.digest(prk, block + info + bytes((counter,)), "sha256")
        okm += block
        counter += 1
    return okm[:length]


def derive_content_key(master, cipher, hkdf=True):
    """The content key gocryptfs derives from a master key for ``cipher``."""
    if hkdf:
        return hkdf_sha256(master, HKDF_INFO[cipher], CONTENT_KEY_LEN[cipher])
    if cipher == "aes-siv":
        return hashlib.sha512(master).digest()
    return bytes(master)


# --------------------------------------------------------------------------
# AEAD backends: cryptography -> pycryptodome -> pure Python
# --------------------------------------------------------------------------

class TagMismatch(Exception):
    """The AEAD tag did not verify (raised by the pycryptodome and pure-Python openers)."""


def _purepy_forced():
    return os.environ.get(PUREPY_ENV, "").strip().lower() in ("1", "true", "yes", "on")


# Known answers for the backend self-test, sealed with cryptography 46.0.3 (and
# checked against pycryptodome and the primitives by the tests): key bytes(range(32))
# (64 for aes-siv), nonce bytes(range(0x40, 0x40 + n)), AAD = block 0 of file id
# bytes(range(16)), plaintext SELFTEST_PLAINTEXT. Keyed by (cipher, nonce length).
SELFTEST_PLAINTEXT = b"memdiver selftest"
SELFTEST_SEALED = {
    ("aes-gcm", 12): "8fdcc3474f4ae271edb7725afd1076280d5231801b65a2e80208ab4021ae417cb3",
    ("aes-gcm", 16): "58e77bbff5293279b9780699f81883d10e9176e029afa437bdf05eba7ab428f0d6",
    ("xchacha", 24): "b95c6814b9961c64af87e2d2c9e800e1e6124ee1230097713ea16261278e825f9a",
    ("aes-siv", 16): "a9ac57ffddc7ecb488fcf9c552a85b0a918ed13653af3e3c94688bc440c1f270b2",
}


def select_backend(cipher, nonce_len=None):
    """``(name, open_block, tag_mismatch_exception)`` of the first WORKING backend.

    ``open_block(key, nonce, sealed, aad)`` returns the plaintext or raises the
    exception. A tier is accepted only after it opens a known answer for this
    cipher and nonce length AND rejects a tampered copy (``_self_test``): an
    importable library can still refuse the algorithm when it is constructed
    (FIPS mode, OpenSSL < 3 without AES-SIV, LibreSSL), and must then fall
    through, not turn every verdict into ``error``. Raises RuntimeError naming
    why every backend is unusable.
    """
    nonce_len = nonce_len or {"xchacha": 24}.get(cipher, 16)
    loaders = [("cryptography", _load_backend), ("pycryptodome", _load_pycryptodome),
               (PURE_PYTHON_BACKEND, _load_pure)]
    if _purepy_forced():
        loaders = loaders[-1:]
    reasons = []
    for name, loader in loaders:
        try:
            open_block, mismatch = loader(cipher)
            _self_test(cipher, nonce_len, open_block, mismatch)
        except Exception as exc:  # RuntimeError names what is missing; else a broken install
            reasons.append(str(exc) if isinstance(exc, RuntimeError) else f"{name}: {exc!r}")
            continue
        return name, open_block, mismatch
    raise RuntimeError(f"no AEAD backend for {cipher}: " + "; ".join(reasons))


def _self_test(cipher, nonce_len, open_block, mismatch):
    """Raise unless ``open_block`` opens the known answer and rejects it tampered."""
    sealed = bytes.fromhex(SELFTEST_SEALED[(cipher, nonce_len)])
    key = bytes(range(CONTENT_KEY_LEN[cipher]))
    nonce, aad = bytes(range(0x40, 0x40 + nonce_len)), struct.pack(">Q", 0) + bytes(range(16))
    if open_block(key, nonce, sealed, aad) != SELFTEST_PLAINTEXT:
        raise ValueError("self-test: known answer opened to the wrong plaintext")
    try:
        open_block(key, nonce, sealed[:-1] + bytes([sealed[-1] ^ 1]), aad)
    except mismatch:
        return
    raise ValueError("self-test: a tampered known answer was accepted")


def _load_backend(cipher):
    """Return ``(open_block, InvalidTag)``; raise RuntimeError naming what is missing."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms
    except ImportError:
        raise RuntimeError(f"backend 'cryptography' is not installed; {cipher} needs it "
                           "(pip install cryptography)") from None
    if cipher == "xchacha":
        return _xchacha_opener(aead, Cipher, algorithms), InvalidTag
    if cipher == "aes-siv":
        return _aes_siv_opener(aead), InvalidTag
    return _aes_gcm_opener(aead), InvalidTag


def _aes_gcm_opener(aead):
    def open_block(key, nonce, sealed, aad):
        return aead.AESGCM(key).decrypt(nonce, sealed, aad)
    return open_block


def _aes_siv_opener(aead):
    aes_siv = getattr(aead, "AESSIV", None)
    if aes_siv is None:
        raise RuntimeError("the installed 'cryptography' has no AESSIV (needs >= 35.0)")

    def open_block(key, nonce, sealed, aad):
        return aes_siv(key).decrypt(sealed, [aad, nonce])
    return open_block


def _xchacha_opener(aead, cipher_cls, algorithms):
    def open_block(key, nonce, sealed, aad):
        subkey = _hchacha20(cipher_cls, algorithms, key, nonce[:16])
        return aead.ChaCha20Poly1305(subkey).decrypt(b"\x00" * 4 + nonce[16:], sealed, aad)
    return open_block


def _load_pycryptodome(cipher):
    """pycryptodome openers; RuntimeError when ``Crypto.Cipher`` is missing or too old."""
    try:
        from Crypto.Cipher import AES, ChaCha20_Poly1305  # nosec B413 -- pycryptodome (maintained), guarded by the self-test
    except Exception:  # ImportError, or the unrelated legacy pycrypto without these ciphers
        raise RuntimeError("backend 'pycryptodome' is not installed") from None
    if cipher == "xchacha":
        return _pycryptodome_xchacha_opener(ChaCha20_Poly1305), TagMismatch
    if cipher == "aes-siv":
        return _pycryptodome_siv_opener(AES), TagMismatch
    return _pycryptodome_gcm_opener(AES), TagMismatch


def _pycryptodome_verified(engine, ciphertext, tag):
    try:
        return engine.decrypt_and_verify(ciphertext, tag)
    except ValueError:  # pycryptodome's "MAC check failed"
        raise TagMismatch("tag mismatch") from None


def _pycryptodome_gcm_opener(aes_cls):
    def open_block(key, nonce, sealed, aad):
        engine = aes_cls.new(key, aes_cls.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        engine.update(aad)
        return _pycryptodome_verified(engine, sealed[:-TAG_LEN], sealed[-TAG_LEN:])
    return open_block


def _pycryptodome_siv_opener(aes_cls):
    # pycryptodome feeds the nonce to S2V as the LAST associated-data element,
    # after every update(): exactly gocryptfs' [aad, nonce] (differential-tested).
    def open_block(key, nonce, sealed, aad):
        engine = aes_cls.new(key, aes_cls.MODE_SIV, nonce=nonce)
        engine.update(aad)
        return _pycryptodome_verified(engine, sealed[TAG_LEN:], sealed[:TAG_LEN])
    return open_block


def _pycryptodome_xchacha_opener(chacha_cls):
    def open_block(key, nonce, sealed, aad):  # a 24-byte nonce selects XChaCha20-Poly1305
        engine = chacha_cls.new(key=key, nonce=nonce)
        engine.update(aad)
        return _pycryptodome_verified(engine, sealed[:-TAG_LEN], sealed[-TAG_LEN:])
    return open_block


def _load_pure(cipher):
    """Openers on the stdlib-only primitives bound as globals ``aes`` / ``chacha``."""
    name = "chacha" if cipher == "xchacha" else "aes"
    primitive = globals().get(name)
    if primitive is None:
        raise RuntimeError(f"pure-Python primitive {name!r} is not loaded")
    if cipher == "xchacha":  # chacha.py has no library path: always pure
        return _pure_tag_last_opener(primitive.xchacha20_poly1305_decrypt), TagMismatch
    # pure=True: aes.py would otherwise quietly use cryptography when it is importable,
    # and this tier is reported (and warned about) as pure Python.
    if cipher == "aes-siv":
        return _pure_siv_opener(functools.partial(primitive.siv_decrypt, pure=True)), TagMismatch
    return _pure_tag_last_opener(functools.partial(primitive.gcm_decrypt, pure=True)), TagMismatch


def _pure_opened(plaintext):
    if plaintext is None:
        raise TagMismatch("tag mismatch")
    return plaintext


def _pure_tag_last_opener(decrypt):
    """GCM / XChaCha: ``decrypt(key, nonce, ct, tag, aad)`` checks the tag before decrypting."""
    def open_block(key, nonce, sealed, aad):
        return _pure_opened(decrypt(key, nonce, sealed[:-TAG_LEN], sealed[-TAG_LEN:], aad))
    return open_block


def _pure_siv_opener(siv_decrypt):
    def open_block(key, nonce, sealed, aad):
        return _pure_opened(siv_decrypt(key, sealed, [aad, nonce]))
    return open_block


def _hchacha20(cipher_cls, algorithms, key, nonce16):
    """HChaCha20 (draft-irtf-cfrg-xchacha-03, section 2.2) from one ChaCha20 block.

    A ChaCha20 block is rounds(state) + state (RFC 8439, section 2.3), and
    cryptography's ChaCha20 takes the 16-byte counter||nonce row verbatim,
    which is exactly where HChaCha20 puts its 16-byte input. Subtracting the
    known input state from that block leaves rounds(state); HChaCha20's output
    is its words 0-3 and 12-15.
    """
    encryptor = cipher_cls(algorithms.ChaCha20(key, nonce16), mode=None).encryptor()
    out = struct.unpack("<16I", encryptor.update(bytes(64)))
    state = _CHACHA_CONSTANTS + struct.unpack("<8I", key) + struct.unpack("<4I", nonce16)
    words = [(out[i] - state[i]) & 0xFFFFFFFF for i in (0, 1, 2, 3, 12, 13, 14, 15)]
    return struct.pack("<8I", *words)


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------

def build_oracle(params, sample):
    """Build a verifier.

    ``params`` (all optional): ``cipher`` ("auto"), ``candidate_is``
    ("master" | "content"), ``hkdf`` (bool, default from FeatureFlags) and
    ``nonce_length`` (12 | 16, aes-gcm without conf only).
    """
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError(f"params must be a dict, not {type(params).__name__}")
    return GocryptfsOracle(params, sample)


def _choose_backend(cipher, nonce_len):
    """``(name, (open_block, mismatch), None)``, or ``(None, None, reason)`` when none works."""
    try:
        name, open_block, mismatch = select_backend(cipher, nonce_len)
    except RuntimeError as exc:
        return None, None, str(exc)
    return name, (open_block, mismatch), None


def _block0_span(meta, body, nonce_len):
    """Bytes of block 0 per the recorded file size; ``truncated`` if the sample lacks them."""
    size = meta.get("file_size")
    available = len(body) if size is None else size - FILE_HEADER_LEN
    want = min(available, nonce_len + BLOCK_PLAINTEXT_MAX + TAG_LEN)
    if len(body) < want:
        return want, f"sample truncated: block 0 needs {want} bytes, sample holds {len(body)}"
    # Also load-bearing for AES-SIV: with an empty plaintext SIV never uses K2 (the
    # CTR half of the key), so a candidate with only K1 right would "authenticate".
    # Refusing an empty block 0 here keeps every proof a proof of the WHOLE key.
    if want <= nonce_len + TAG_LEN:
        return want, f"sample truncated: block 0 is {want} bytes, too short for any plaintext"
    return want, None


def _split_block0(body, span):
    block = body[:span]
    if not block.strip(b"\x00"):
        raise ValueError("block 0 is an all-zero sparse hole; pick another content file")
    return block


class GocryptfsOracle:
    """Verifies candidates against block 0 of one gocryptfs content file."""

    # One vault sample admits exactly one key (a 128-bit tag over the file's own block 0),
    # so a generated plugin may stop verifying once a candidate is proven.
    unique = True

    def __init__(self, params, sample):
        parsed = parse_sample(sample)
        flags = parsed["meta"].get("feature_flags")
        self.cipher = resolve_cipher(params.get("cipher"), parsed["meta"].get("cipher"), flags)
        self.hkdf = _resolve_hkdf(params.get("hkdf"), flags, self.cipher)
        self.candidate_is = _resolve_candidate_is(params.get("candidate_is"))
        self.file_id = parsed["file_id"]
        nonce_len = nonce_length(self.cipher, flags, params.get("nonce_length"), self.hkdf)
        span, self.truncation = _block0_span(parsed["meta"], parsed["body"], nonce_len)
        block = _split_block0(parsed["body"], span)
        self.nonce, self.sealed = block[:nonce_len], block[nonce_len:]
        self.aad = struct.pack(">Q", 0) + self.file_id
        key_len = MASTER_KEY_LEN if self.candidate_is == "master" else CONTENT_KEY_LEN[self.cipher]
        self.candidate_lengths = (key_len,)
        self.backend, self._backend, self.backend_error = _choose_backend(self.cipher, nonce_len)

    def content_key(self, candidate):
        if self.candidate_is == "content":
            return bytes(candidate)
        return derive_content_key(candidate, self.cipher, self.hkdf)

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises. ``ctx`` is accepted and unused."""
        try:
            return self._verify(candidate)
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", f"verify failed: {exc!r}")

    def _verify(self, candidate):
        if not isinstance(candidate, (bytes, bytearray, memoryview)):
            return self._verdict("error", f"candidate must be bytes, not {type(candidate).__name__}")
        if self.truncation:
            return self._verdict("error", self.truncation)
        if len(candidate) not in self.candidate_lengths:
            return self._verdict("rejected", f"candidate is {len(candidate)} bytes; a "
                                 f"{self.cipher} {self.candidate_is} key is "
                                 f"{self.candidate_lengths[0]}")
        try:
            open_block, invalid_tag = self._load()
        except RuntimeError as exc:
            return self._verdict("error", str(exc))
        try:
            key = self.content_key(bytes(candidate))
            plaintext = open_block(key, self.nonce, self.sealed, self.aad)
        except invalid_tag:
            return self._verdict("rejected", f"{self.cipher} tag mismatch on block 0")
        except Exception as exc:  # a backend failure is not a verdict on the key
            return self._verdict("error", f"{self.cipher} open failed: {exc!r}")
        return self._verdict("proven", f"{self.cipher} block 0 authenticated",
                             self._evidence(key, plaintext))

    def _load(self):
        if self._backend is None:
            raise RuntimeError(self.backend_error)
        return self._backend

    def _evidence(self, key, plaintext):
        return {"cipher": self.cipher, "candidate_is": self.candidate_is, "hkdf": self.hkdf,
                "backend": self.backend,
                "content_key_hex": key.hex(), "file_id_hex": self.file_id.hex(),
                "block_no": 0, "plaintext_len": len(plaintext),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest()}

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
