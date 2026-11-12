"""SSH-2 key derivation (RFC 4253 section 7.2) for memory self-consistency proofs.

An SSH session derives its six keys from three values that the key exchange leaves
behind -- the shared secret ``K``, the exchange hash ``H`` and the ``session_id``
(``H`` of the first key exchange)::

    K1 = HASH(K || H || X || session_id)        X = "A" .. "F"
    Kn = HASH(K || H || K1 || ... || K(n-1))    (extension, when more bytes are needed)
    key = (K1 || K2 || ...)[:needed]

    A = IV client->server     B = IV server->client
    C = encryption c->s       D = encryption s->c
    E = integrity (MAC) c->s  F = integrity (MAC) s->c

``K`` enters the hash ENCODED: as an ``mpint`` (RFC 4251 section 5: big endian, no
redundant leading zero byte, one 0x00 prepended when the top bit is set) for the classic
and curve25519/ECDH exchanges, and as a ``string`` (raw bytes, length prefixed) for the
hybrid post-quantum exchanges ``sntrup761x25519-sha512`` and ``mlkem768x25519-sha256``,
whose K is itself a hash output. A key of N bytes is always the N-byte PREFIX of the
longer derivation, so one 64-byte derivation per letter answers every key length.

The proof this module supports (``ssh-kdf-consistency``): when (K, H, session_id) are
found in a process's memory and at least TWO of the keys derived from them are found in
the SAME memory, the triple and those keys are the session's -- a SHA-2 output that
matches 96+ bits of a second, independent memory location by chance is not a thing. One
match is reported, but is not called a proof.

Self-contained (see ``__init__``): standard library only, paste-safe, private names carry
the ``_sshkdf_`` prefix. Used by ``memdiver.ssh`` (``vol3plugins/memdiver/ssh.py``) and by
the format oracle ``oracles/formats/ssh_kdf_consistency.py``.
"""
import hashlib
import struct

LETTERS = "ABCDEF"
LETTER_ROLE = {
    "A": ("iv", "c2s"), "B": ("iv", "s2c"),
    "C": ("key", "c2s"), "D": ("key", "s2c"),
    "E": ("mac", "c2s"), "F": ("mac", "s2c"),
}
#: Hash output size -> hash name (the size of H tells the kex hash for every RFC kex).
HASH_BY_SIZE = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}
#: Enough material for every SSH key: chacha20-poly1305@openssh.com takes 64 bytes.
MAX_DERIVED = 64
#: Shortest prefix that counts as a match (96 bits: a GCM IV; no chance collision).
MIN_MATCH = 12
K_ENCODINGS = ("mpint", "string")
#: Distinct derived keys (letters) that must be found for a proof.
MIN_PROVEN_LETTERS = 2

#: Cipher name -> (key_len, iv_len, block_size, auth_len), as OpenSSH's cipher.c lists them.
CIPHERS = {
    "chacha20-poly1305@openssh.com": (64, 0, 8, 16),
    "aes128-ctr": (16, 16, 16, 0), "aes192-ctr": (24, 16, 16, 0), "aes256-ctr": (32, 16, 16, 0),
    "aes128-gcm@openssh.com": (16, 12, 16, 16), "aes256-gcm@openssh.com": (32, 12, 16, 16),
    "aes128-cbc": (16, 16, 16, 0), "aes192-cbc": (24, 16, 16, 0), "aes256-cbc": (32, 16, 16, 0),
    "3des-cbc": (24, 8, 8, 0),
}
#: MAC name -> key length (the "-etm@openssh.com" variants take the same key).
MACS = {
    "hmac-sha1": 20, "hmac-sha1-96": 20, "hmac-sha2-256": 32, "hmac-sha2-512": 64,
    "hmac-md5": 16, "umac-64@openssh.com": 16, "umac-128@openssh.com": 16,
}
#: Key exchanges whose K is hashed as a ``string`` instead of an ``mpint``.
STRING_K_KEX = ("sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
                "mlkem768x25519-sha256")


def backend():
    """Which implementation runs (always hashlib from the standard library)."""
    return "pure-python"


def kex_hash(kex_name):
    """The hash of a kex method name (``curve25519-sha256`` -> ``sha256``), or ``None``."""
    name = (kex_name or "").lower()
    for suffix in ("sha512", "sha384", "sha256", "sha1"):
        if suffix in name:
            return suffix
    return None


def kex_k_encoding(kex_name):
    """``"string"`` for the hybrid PQ exchanges, else ``"mpint"``."""
    name = (kex_name or "").lower()
    return "string" if any(name.startswith(k.split("@")[0]) for k in STRING_K_KEX) else "mpint"


def mac_key_length(mac_name):
    """Key length of an SSH MAC name (etm variants included), or ``None``."""
    name = (mac_name or "").replace("-etm@openssh.com", "")
    return MACS.get(name)


def encode_mpint(value):
    """RFC 4251 mpint of a non-negative integer given as ``int`` or big-endian bytes.

    Leading zero bytes are dropped (they "MUST NOT be included") and one 0x00 is put back
    when the top bit of the first remaining byte is set; zero encodes as an empty string.
    """
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative mpint values do not occur as SSH shared secrets")
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    else:
        raw = bytes(value).lstrip(b"\x00")
    if raw and raw[0] & 0x80:
        raw = b"\x00" + raw
    return struct.pack(">I", len(raw)) + raw


def encode_string(value):
    """RFC 4251 string: 4-byte big-endian length, then the bytes unchanged."""
    raw = bytes(value)
    return struct.pack(">I", len(raw)) + raw


def encode_shared_secret(value, encoding="mpint"):
    """K as it enters the hash. ``encoding``: ``mpint``, ``string`` or ``encoded`` (as is)."""
    if encoding == "mpint":
        return encode_mpint(value)
    if encoding == "string":
        return encode_string(value)
    if encoding == "encoded":
        return bytes(value)
    raise ValueError("unknown K encoding %r" % (encoding,))


def is_encoded(blob):
    """True when ``blob`` is one length-prefixed SSH string/mpint and nothing else."""
    blob = bytes(blob)
    return len(blob) >= 4 and struct.unpack(">I", blob[:4])[0] == len(blob) - 4


def _sshkdf_new(hash_name):
    try:
        return hashlib.new(hash_name)
    except (ValueError, TypeError):
        raise ValueError("unsupported SSH kex hash %r" % (hash_name,))


def _sshkdf_prefix(k_encoded, exchange_hash, hash_name):
    """The hash state after ``K || H``, the common prefix of every digest of one exchange."""
    prefix = _sshkdf_new(hash_name)
    prefix.update(bytes(k_encoded))
    prefix.update(bytes(exchange_hash))
    return prefix


def _sshkdf_expand(prefix, letter, session_id, length):
    """``length`` bytes for ``letter``: ``K1 = HASH(prefix || X || session_id)``, then
    ``Kn = HASH(prefix || K1 || ... || K(n-1))`` (copies of the shared prefix state)."""
    first = prefix.copy()
    first.update(letter.encode("ascii"))
    first.update(session_id)
    parts = [first.digest()]
    while sum(len(p) for p in parts) < length:
        more = prefix.copy()
        more.update(b"".join(parts))
        parts.append(more.digest())
    return b"".join(parts)[:length]


def _sshkdf_check(letter, length):
    if letter not in LETTERS or len(letter) != 1:
        raise ValueError("letter must be one of A..F, not %r" % (letter,))
    if length < 0:
        raise ValueError("length must be >= 0")


def derive_key(k_encoded, exchange_hash, letter, session_id, length, hash_name="sha256"):
    """One derived key: ``length`` bytes for ``letter`` (A..F); K is already encoded."""
    _sshkdf_check(letter, length)
    prefix = _sshkdf_prefix(k_encoded, exchange_hash, hash_name)
    return _sshkdf_expand(prefix, letter, bytes(session_id), length)


def derive_all(k_encoded, exchange_hash, session_id, length=MAX_DERIVED, hash_name="sha256"):
    """``{letter: key}`` for A..F, each ``length`` bytes (``K || H`` is hashed once)."""
    _sshkdf_check(LETTERS[0], length)
    prefix = _sshkdf_prefix(k_encoded, exchange_hash, hash_name)
    session_id = bytes(session_id)
    return {letter: _sshkdf_expand(prefix, letter, session_id, length) for letter in LETTERS}


def guess_hash(exchange_hash):
    """The kex hash implied by the size of H, or ``None``."""
    return HASH_BY_SIZE.get(len(exchange_hash))


def match_length(derived, candidate):
    """Length of the common prefix of ``derived`` and ``candidate``."""
    limit = min(len(derived), len(candidate))
    index = 0
    while index < limit and derived[index] == candidate[index]:
        index += 1
    return index


def swap_words(blob):
    """Reverse the bytes of every 4-byte word (keys loaded as big-endian u32 words)."""
    blob = bytes(blob)
    whole = len(blob) - len(blob) % 4
    return b"".join(blob[i:i + 4][::-1] for i in range(0, whole, 4)) + blob[whole:]


def matched_letters(derived, found, min_match=MIN_MATCH):
    """Which derived keys occur among ``found`` byte strings.

    ``derived``: ``{letter: material}`` from :func:`derive_all`. ``found``: an iterable of
    byte strings recovered from memory (keys, IVs, MAC keys, chacha halves). A found
    string matches a letter when it equals a prefix of that letter's material of at least
    ``min_match`` bytes, or the second 32-byte half (chacha20-poly1305 keeps its two
    32-byte keys apart), in natural or word-swapped byte order.
    Returns ``{letter: (offset_in_material, length, swapped)}`` (best match per letter).
    """
    best = {}
    for blob in found:
        blob = bytes(blob)
        if len(blob) < min_match:
            continue
        for letter, material in derived.items():
            for swapped, view in ((False, blob), (True, swap_words(blob))):
                for offset in (0, 32):
                    length = match_length(material[offset:], view)
                    if length >= min(len(view), MAX_DERIVED - offset) and length >= min_match:
                        if length > best.get(letter, (0, 0, False))[1]:
                            best[letter] = (offset, length, swapped)
    return best


def proof_status(letter_count, trusted=False):
    """The ``ssh-kdf-consistency`` rule: ``proven`` (>= 2 letters found), ``rejected``
    (none found although the found keys are trusted to be this session's) or
    ``inconclusive`` (one letter, or none without trust) -- never a proof."""
    if letter_count >= MIN_PROVEN_LETTERS:
        return "proven"
    if letter_count == 0 and trusted:
        return "rejected"
    return "inconclusive"
