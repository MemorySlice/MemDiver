"""Verify-once + random-access decryption of an MSL AEAD container (spec §10).

The on-disk format is unchanged: ONE AEAD over the whole block stream,
``[Header 128B | KEM ct | ciphertext | Tag 16B]`` with AAD = header + KEM ct.
Instead of decrypting it one-shot into a heap buffer (≈1-2× file size of RAM),
the reader:

1. **verifies** the tag in a single bounded pass over the mmap'd ciphertext
   (:func:`verify_tag_streaming`), and only then
2. **decrypts on demand** any ``[off, off + len)`` of the plaintext through the
   AEAD's underlying stream cipher (:class:`SeekableDecryptor`), served to the
   reader as a :class:`DecryptedView` with a small LRU page cache.

Keystream positions
-------------------
* AES-256-GCM with a 96-bit nonce: ``J0 = nonce || 0x00000001`` (tag mask);
  ciphertext block *i* uses counter block ``nonce || be32(2 + i)`` with the
  GCM ``inc32`` rule (only the low 32 bits increment, wrapping mod 2^32).
  GCM caps one message at 2^39 - 256 bits = 2^32 - 2 blocks (~64 GiB), so the
  highest counter used is 2^32 - 1 and the wrap is never reached by a valid
  message; :func:`_aes_ctr32` still splits at the wrap so the arithmetic is
  inc32-exact by construction.
* XChaCha20-Poly1305 (IETF): sub-key = HChaCha20(key, nonce[:16]); ChaCha20
  nonce = ``4 zero bytes || nonce[16:24]``; block 0 is the Poly1305 key and
  data block *i* uses the 32-bit counter ``1 + i``. libsodium caps a message
  at 64 × (2^32 - 1) bytes (~256 GiB); reads past that are refused.

Integrity / TOCTOU
------------------
:class:`FileIdentity` records ``(st_dev, st_ino, st_size, st_mtime_ns,
st_ctime_ns)`` of the open file descriptor at verification time; every read
that touches ciphertext re-``fstat``s the descriptor *after* copying it and
raises :class:`MslSourceChangedError` if anything changed. Residual risk: a
modification that leaves all five fields untouched (same-tick write on a
coarse-timestamp filesystem, writes through a shared mapping not yet flushed
to the inode, or a privileged actor rewriting ctime via the clock) is not
detected; such bytes decrypt to unauthenticated plaintext. See the spec's
implementation notes.

Key material: the content key lives in a ``bytearray`` shared with the
reader's :class:`~memdiver.msl.crypto.RewrapMaterial`, so the single
``wipe()`` on ``close()`` zeroises both; the XChaCha sub-key is held in its
own ``bytearray`` and wiped by :meth:`SeekableDecryptor.wipe`.
"""

import hmac
import os
import struct
from collections import OrderedDict
from typing import NamedTuple, Optional

from .aead_stream import hchacha20
from .enums import EncAlgo
from .types import MslAuthError, MslCryptoError

#: Bounded chunk for the verification pass (and the size of one cache page).
VERIFY_CHUNK = 1 << 20
CACHE_PAGE = 256 << 10   # multiple of 16 (AES block) and 64 (ChaCha block)
CACHE_PAGES = 16         # 16 × 256 KiB = 4 MiB LRU of decrypted pages
TAG_LEN = 16

_GCM_MAX_PLAINTEXT = (1 << 36) - 32          # 2^39 - 256 bits, in bytes
_CHACHA_MAX_PLAINTEXT = 64 * ((1 << 32) - 1)  # libsodium IETF limit

#: Set to ``1`` to fall back to the legacy one-shot decrypt (debugging only).
ONESHOT_ENV = "MEMDIVER_MSL_DECRYPT_ONESHOT"


def oneshot_requested() -> bool:
    return os.environ.get(ONESHOT_ENV, "").strip() not in ("", "0")


class MslSourceChangedError(MslAuthError):
    """The encrypted file changed after its tag was verified."""


# ---------------------------------------------------------------- identity

class FileIdentity(NamedTuple):
    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def of_fd(cls, fd: int) -> "FileIdentity":
        st = os.fstat(fd)
        return cls(st.st_dev, st.st_ino, st.st_size,
                   st.st_mtime_ns, st.st_ctime_ns)


class FileGuard:
    """Rejects reads once the file behind *fd* differs from the verified one."""

    def __init__(self, fd: int, identity: FileIdentity, path: object = None):
        self._fd = fd
        self._identity = identity
        self._path = path

    def check(self) -> None:
        try:
            now = FileIdentity.of_fd(self._fd)
        except OSError as exc:
            raise MslSourceChangedError(
                f"{self._path}: cannot re-check encrypted source: {exc}") from exc
        if now != self._identity:
            raise MslSourceChangedError(
                f"{self._path}: encrypted MSL file changed after its AEAD tag "
                "was verified (size/mtime/ctime/inode differ); reopen it")


# ------------------------------------------------------------ verification

def verify_tag_streaming(algo: EncAlgo, key, nonce: bytes, aad: bytes,
                         ciphertext, tag: bytes,
                         chunk: int = VERIFY_CHUNK) -> None:
    """Authenticate ``ciphertext`` (any buffer, read in *chunk* slices).

    Raises :class:`MslAuthError` on a mismatch — the same error the one-shot
    :func:`memdiver.msl.crypto.aead_decrypt` raises. No plaintext escapes.
    """
    if len(tag) != TAG_LEN:
        raise MslAuthError("AEAD tag missing (container truncated)")
    view = memoryview(ciphertext)
    try:
        if algo == EncAlgo.AES_256_GCM:
            _verify_gcm(key, nonce, aad, view, tag, chunk)
        elif algo == EncAlgo.XCHACHA20_POLY1305:
            _verify_xchacha(key, nonce, aad, view, tag, chunk)
        else:
            raise MslCryptoError(f"Unsupported cipher suite: {algo}")
    finally:
        view.release()


def _verify_gcm(key, nonce, aad, view, tag, chunk) -> None:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(view) > _GCM_MAX_PLAINTEXT:
        raise MslAuthError("AES-256-GCM message exceeds 2^39-256 bits")
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    dec.authenticate_additional_data(aad)
    sink = bytearray(chunk + 15)   # plaintext is discarded: unverified
    for start in range(0, len(view), chunk):
        dec.update_into(view[start:start + chunk], sink)
    try:
        dec.finalize()             # constant-time tag check inside OpenSSL
    except InvalidTag:
        raise MslAuthError("AEAD tag verification failed (AES-256-GCM)")
    finally:
        sink[:] = bytes(len(sink))


def _verify_xchacha(key, nonce, aad, view, tag, chunk) -> None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    if len(nonce) != 24:
        raise MslCryptoError("XChaCha20-Poly1305 needs a 24-byte nonce")
    subkey = bytearray(hchacha20(bytes(key), nonce[:16]))
    try:
        iv = b"\x00" * 8 + nonce[16:24]  # LE32 counter 0 || IETF nonce
        block0 = Cipher(algorithms.ChaCha20(subkey, iv), mode=None).encryptor()
        poly_key = bytearray(block0.update(b"\x00" * 64)[:32])
    finally:
        subkey[:] = bytes(32)
    mac = Poly1305(poly_key)
    poly_key[:] = bytes(32)
    mac.update(aad)
    mac.update(_pad16(len(aad)))
    for start in range(0, len(view), chunk):
        mac.update(view[start:start + chunk])  # Poly1305 is over ciphertext
    mac.update(_pad16(len(view)))
    mac.update(struct.pack("<QQ", len(aad), len(view)))
    if not hmac.compare_digest(mac.finalize(), tag):
        raise MslAuthError("AEAD tag verification failed (XChaCha20-Poly1305)")


def _pad16(n: int) -> bytes:
    return b"\x00" * (-n % 16)


# -------------------------------------------------------- random access

def _aes_ctr32(key, nonce12: bytes, counter: int, data) -> bytes:
    """AES-CTR with GCM ``inc32`` semantics starting at 32-bit *counter*.

    ``cryptography``'s CTR increments the full 128-bit block; GCM increments
    only the low 32 bits. The two agree until the low word wraps, so the
    input is split at the wrap and the second part restarts at counter 0.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    counter &= 0xFFFFFFFF
    room = ((1 << 32) - counter) * 16       # bytes before the low word wraps
    head, tail = data[:room], data[room:]
    iv = nonce12 + struct.pack(">I", counter)
    out = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor().update(head)
    if len(tail):
        out += _aes_ctr32(key, nonce12, 0, tail)
    return out


class SeekableDecryptor:
    """Decrypts any plaintext range of a verified AEAD ciphertext."""

    def __init__(self, algo: EncAlgo, key: bytearray, nonce: bytes):
        self.algo = algo
        if algo == EncAlgo.AES_256_GCM:
            if len(nonce) != 12:
                raise MslCryptoError("AES-256-GCM seek needs a 96-bit nonce")
            self._key = key                 # shared with RewrapMaterial
            self._nonce = bytes(nonce)
            self._align = 16
            self._limit = _GCM_MAX_PLAINTEXT
        elif algo == EncAlgo.XCHACHA20_POLY1305:
            if len(nonce) != 24:
                raise MslCryptoError("XChaCha20-Poly1305 needs a 24-byte nonce")
            self._key = bytearray(hchacha20(bytes(key), nonce[:16]))
            self._nonce = b"\x00" * 4 + bytes(nonce[16:24])
            self._align = 64
            self._limit = _CHACHA_MAX_PLAINTEXT
        else:
            raise MslCryptoError(f"Unsupported cipher suite: {algo}")
        self._owns_key = algo != EncAlgo.AES_256_GCM

    def decrypt(self, ciphertext, offset: int) -> bytes:
        """Plaintext of ``ciphertext`` (a slice starting at stream *offset*).

        *offset* must be a multiple of the cipher block (16 / 64): callers
        widen their window to the block boundary and trim afterwards.
        """
        if not any(self._key):
            raise MslCryptoError("decryption key has been wiped (reader closed)")
        if offset % self._align:
            raise ValueError(f"offset {offset} not {self._align}-byte aligned")
        if offset + len(ciphertext) > self._limit:
            raise MslCryptoError(f"{self.algo.name}: read beyond the cipher's "
                                 "per-message limit")
        block = offset // self._align
        if self.algo == EncAlgo.AES_256_GCM:
            return _aes_ctr32(self._key, self._nonce, 2 + block, ciphertext)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        iv = struct.pack("<I", 1 + block) + self._nonce
        return Cipher(algorithms.ChaCha20(self._key, iv),
                      mode=None).encryptor().update(ciphertext)

    @property
    def align(self) -> int:
        return self._align

    def wipe(self) -> None:
        """Zeroise key bytes this object owns (the GCM key is the reader's)."""
        if self._owns_key:
            self._key[:] = bytes(len(self._key))


class DecryptedView:
    """Read-only, lazily decrypted plaintext of an authenticated container.

    Behaves like the ``bytes`` the one-shot path produced for everything the
    reader does with its block buffer: ``len()``, ``view[i]`` (int),
    ``view[a:b]`` (``bytes``) and :meth:`read`. Small reads go through an LRU
    of decrypted :data:`CACHE_PAGE` pages (block-header walks touch the same
    page repeatedly); reads larger than a page are decrypted directly and not
    cached. Every ciphertext access re-checks the file identity.
    """

    def __init__(self, ciphertext, decryptor: SeekableDecryptor,
                 guard: Optional[FileGuard], *,
                 page_size: int = CACHE_PAGE, max_pages: int = CACHE_PAGES):
        self._ct = ciphertext            # memoryview over the mmap (no tag)
        self._dec = decryptor
        self._guard = guard
        self._page = page_size
        self._max_pages = max_pages
        self._cache: "OrderedDict[int, bytes]" = OrderedDict()
        self._closed = False

    def __len__(self) -> int:
        return 0 if self._closed else len(self._ct)

    def __getitem__(self, item):
        if isinstance(item, slice):
            start, stop, step = item.indices(len(self))
            if step != 1:
                return self.read(start, max(0, stop - start))[::step]
            return self.read(start, max(0, stop - start))
        index = item + len(self) if item < 0 else item
        if not 0 <= index < len(self):
            raise IndexError("DecryptedView index out of range")
        return self.read(index, 1)[0]

    def read(self, offset: int, length: int) -> bytes:
        """Plaintext ``[offset, offset + length)``, clamped to the stream."""
        if self._closed:
            raise MslCryptoError("encrypted reader is closed")
        size = len(self._ct)
        offset = max(0, offset)
        end = min(size, offset + max(0, length))
        if end <= offset:
            return b""
        first, last = offset // self._page, (end - 1) // self._page
        if last - first <= 1 and end - offset <= self._page:
            return self._read_cached(offset, end, first, last)
        return self._decrypt_range(offset, end)

    def _read_cached(self, offset: int, end: int, first: int, last: int) -> bytes:
        pages = [self._page_bytes(p) for p in range(first, last + 1)]
        joined = pages[0] if len(pages) == 1 else b"".join(pages)
        base = first * self._page
        return joined[offset - base:end - base]

    def _page_bytes(self, index: int) -> bytes:
        page = self._cache.get(index)
        if page is not None:
            self._cache.move_to_end(index)
            return page
        start = index * self._page
        page = self._decrypt_range(start, min(len(self._ct), start + self._page))
        self._cache[index] = page
        while len(self._cache) > self._max_pages:
            self._cache.popitem(last=False)
        return page

    def _decrypt_range(self, offset: int, end: int) -> bytes:
        aligned = offset - offset % self._dec.align
        plain = self._dec.decrypt(self._ct[aligned:end], aligned)
        if self._guard is not None:
            self._guard.check()     # after the copy: catches a racing write
        skip = offset - aligned
        return plain[skip:] if skip else plain

    def close(self) -> None:
        """Drop cached plaintext, release the mmap view, wipe owned keys."""
        self._closed = True
        self._cache.clear()
        self._dec.wipe()
        if isinstance(self._ct, memoryview):
            self._ct.release()
