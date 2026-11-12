"""SSH session-key recovery from one process's memory, with honest proof tiers.

This module is the analysis behind the ``memdiver.ssh.SSHKeys`` Volatility 3 plugin. It
works on plain bytes (a :class:`Memory` of ``(virtual address, bytes)`` segments), knows
nothing about Volatility, and imports only the standard library and the stdlib-only
primitives of ``vol3plugins/linux/secrets`` -- so it is unit-tested on synthetic memory
and runs unchanged under stock ``vol``.

Tiers (the ``Tier`` column of every row)
---------------------------------------
``A`` -- full KDF proof, memory only. A locator finds the key-exchange output the
         implementation keeps -- shared secret ``K``, exchange hash ``H``, ``session_id`` --
         the six RFC 4253 keys A..F are re-derived from it, and the derived keys are
         searched in the SAME memory. Two or more distinct letters found is a proof
         (``Proven = oracle:ssh-kdf-consistency``, the rule of the format oracle of that
         name). Locators: Go ``x/crypto/ssh`` (``kexResult`` slice header), Paramiko /
         CPython (``Transport.K`` int + ``H``/``session_id`` bytes objects), libssh
         (``ssh_crypto_struct``: ``session_id_len, session_id, digest_len, secret_hash``
         + the ``shared_secret`` BIGNUM), wolfSSH (inline ``h``, ``k``, ``sessionId``), and a generic one for an encoded K that is still resident (an OpenSSH
         ``sshbuf`` holding ``mpint``/``string`` K next to the ``session_id`` sshbuf).
``B`` -- OpenSSH structural validation (the Fox-IT 2020 baseline): ``struct newkeys`` ->
         ``sshenc{name, cipher, enabled, key_len, iv_len, block_size, key, iv}`` whose
         name string, ``struct sshcipher`` and lengths agree; direction from the
         ``newkeys[MODE_MAX]`` pointer pair. ``unverified``: OpenSSH wipes K after
         ``kex_derive_keys``. If K is still resident, the generic Tier A locator proves
         the same keys and the row is Tier A instead.
``C`` -- cipher-state consistency only (Dropbear/libtomcrypt, libssh2, OpenSSH built
         without OpenSSL): a ChaCha20 state pair (``"expand 32-byte k"`` + key words,
         rounds 20; the two 32-byte halves of the chacha20-poly1305@openssh.com key) or an
         AES key schedule that re-expands from its first round key. ``unverified``: it
         shows a cipher key in use, not which session derived it.

Tier A key lengths and algorithm names come from the negotiated algorithms the
implementation stored when they are found (libssh ``ssh_crypto_struct.kex_methods``, the
OpenSSH ``sshenc`` whose key buffer is the proven key), else they are inferred from the
cipher state in memory; the row detail says which (``lengths: negotiated(libssh)`` /
``lengths: inferred``).

``rejected`` is only ever produced by a trusted Tier A structure (K, H and the derived-key
buffers read from the SAME implementation struct) whose re-derived keys do not match.
"""
import re
import struct
from bisect import bisect_right

from ..linux.secrets import aes, ssh_kdf

ORACLE_KIND = "ssh-kdf-consistency"
PROVEN = "oracle:" + ORACLE_KIND
UNVERIFIED = "unverified"
REJECTED = "rejected"
HASH_SIZES = (20, 32, 48, 64)
CRYPTO_HASH_IDS = {3: "sha1", 5: "sha256", 6: "sha384", 7: "sha512"}  # Go crypto.Hash
MAX_POINTER = 1 << 56          # canonical user-space bound, 5-level paging included
MIN_POINTER = 0x10000
MAX_COMBINATIONS = 50000       # (K, H, session_id) triples evaluated per process
SERVER_NAMES = ("sshd", "sshd-session", "sshd-auth", "dropbear", "wolfsshd")
CLIENT_NAMES = ("ssh", "dbclient", "scp", "sftp")
CHACHA_CONSTANTS = b"expand 32-byte k"
SSHBUF_SIZE_MAX = 0x8000000    # OpenSSH sshbuf.h


def _pointer(value):
    return MIN_POINTER <= value < MAX_POINTER


def _distinct(blob):
    return len(set(blob))


def high_entropy(blob):
    """Cheap randomness test for keys/hashes: enough distinct byte values for the length."""
    if not blob:
        return False
    need = {8: 6, 12: 9, 16: 11, 20: 13, 24: 15, 32: 19, 48: 26, 64: 33}
    return _distinct(blob) >= need.get(len(blob), max(6, int(len(blob) * 0.5)))


class Memory(object):
    """Readable bytes of one process: sorted, non-overlapping ``(va, bytes)`` segments."""

    def __init__(self, segments):
        runs = []   # [start va, [pieces], end va]: contiguous pieces are joined once, at the end
        for va, data in sorted((int(va), bytes(data)) for va, data in segments if data):
            if runs and runs[-1][2] == va:
                runs[-1][1].append(data)
                runs[-1][2] += len(data)
            else:
                runs.append([va, [data], va + len(data)])
        merged = [(va, pieces[0] if len(pieces) == 1 else b"".join(pieces))
                  for va, pieces, _end in runs]
        self.segments = merged
        self._starts = [va for va, _ in merged]

    @property
    def size(self):
        return sum(len(data) for _, data in self.segments)

    def read(self, va, length):
        """``length`` bytes at ``va`` from one segment, or ``None`` when not all readable."""
        index = bisect_right(self._starts, va) - 1
        if index < 0 or length < 0:
            return None
        start, data = self.segments[index]
        offset = va - start
        if offset + length > len(data):
            return None
        return data[offset:offset + length]

    def qword(self, va):
        raw = self.read(va, 8)
        return None if raw is None else struct.unpack("<Q", raw)[0]

    def dword(self, va):
        raw = self.read(va, 4)
        return None if raw is None else struct.unpack("<I", raw)[0]

    def cstring(self, va, limit=64):
        raw = self.read(va, limit) if va else None
        if raw is None or b"\x00" not in raw:
            return None
        text = raw.split(b"\x00", 1)[0]
        try:
            return text.decode("ascii")
        except UnicodeDecodeError:
            return None

    def find_all(self, needle, limit=64):
        """Every VA where ``needle`` starts (at most ``limit``)."""
        hits = []
        for start, data in self.segments:
            position = data.find(needle)
            while position >= 0 and len(hits) < limit:
                hits.append(start + position)
                position = data.find(needle, position + 1)
        return hits

    def finditer(self, pattern, align=1, scout=None, lead=0):
        """``(va, match)`` for a compiled bytes regex, keeping ``va % align == 0``.

        With ``scout`` (a cheap regex for a distinctive field ``lead`` bytes into the
        struct), only scout hits are tried: ``pattern`` is then matched at ``hit - lead``.
        A pattern that starts with "any 8 bytes" costs a regex step at every byte; the
        scout starts with a literal or a narrow class and runs at C speed.
        """
        for start, data in self.segments:
            if scout is None:
                for match in pattern.finditer(data):
                    va = start + match.start()
                    if va % align == 0:
                        yield va, match
                continue
            for hit in scout.finditer(data):
                position = hit.start() - lead
                if position < 0 or (start + position) % align:
                    continue
                match = pattern.match(data, position)
                if match:
                    yield start + position, match


# --------------------------------------------------------------------------- findings


class KexTuple(object):
    """One (K, H, session_id) candidate and where it was read."""

    def __init__(self, implementation, k_options, exchange_hash, session_id, hash_name=None,
                 where=None, trusted_found=None, locator="", negotiated=None):
        self.implementation = implementation
        self.negotiated = negotiated            # Negotiated algorithms the struct stores, or None
        self.k_options = tuple(k_options)       # encoded K bytes (with the length prefix)
        self.exchange_hash = bytes(exchange_hash)
        self.session_id = bytes(session_id or exchange_hash)
        self.hash_name = hash_name
        self.where = dict(where or {})
        self.trusted_found = list(trusted_found or [])  # [(label, va, bytes)]
        self.locator = locator

    def key(self):
        return (self.k_options, self.exchange_hash, self.session_id)


class Negotiated(object):
    """Algorithms an implementation stored for its session: ``{direction: (cipher, mac)}``
    (``mac`` may be None) and where they were read (``source``, e.g. ``libssh``)."""

    def __init__(self, source, by_direction):
        self.source = source
        self.by_direction = dict(by_direction)


class KeyRow(object):
    """One output row (a key, IV or MAC key) with its tier and verdict."""

    def __init__(self, implementation, tier, direction, kind, cipher, key, addresses,
                 proven, detail, letter="", locator=""):
        self.implementation = implementation
        self.tier = tier
        self.direction = direction
        self.kind = kind
        self.cipher = cipher
        self.key = bytes(key)
        self.addresses = sorted(set(addresses))
        self.proven = proven
        self.detail = detail
        self.letter = letter
        self.locator = locator

    def as_dict(self):
        return {"implementation": self.implementation, "tier": self.tier,
                "direction": self.direction, "kind": self.kind, "letter": self.letter,
                "cipher": self.cipher, "key_hex": self.key.hex(), "length": len(self.key),
                "addresses": ["0x%x" % a for a in self.addresses], "proven": self.proven,
                "detail": self.detail, "locator": self.locator}


# --------------------------------------------------------------------------- Tier A locators

# Every struct pattern is a lookahead: matches may overlap, and a look-alike that fails the
# Python-side checks must not swallow the real struct a few bytes later.
_GO_SCOUT = re.compile(rb"(?=[\x14\x20\x30\x40]\x00{7}[\s\S]{80}[\x03\x05\x06\x07]\x00{7})")
_GO_KEXRESULT = re.compile(
    rb"(?s)(?=(.{8})([\x14\x20\x30\x40]\x00{7})(.{8})"   # H ptr, len, cap
    rb"(.{8})(.{8})(.{8})"                               # K
    rb"(.{8})(.{8})(.{8})"                               # HostKey
    rb"(.{8})(.{8})(.{8})"                               # Signature
    rb"([\x03\x05\x06\x07]\x00{7})"                     # Hash crypto.Hash
    rb"(.{8})([\x14\x20\x30\x40]\x00{7})(.{8}))")        # SessionID


def _slice(memory, ptr, length, cap, max_len=1 << 16):
    if not _pointer(ptr) or not 0 < length <= cap or cap > max_len:
        return None
    return memory.read(ptr, length)


def find_go_kex_results(memory):
    """golang.org/x/crypto/ssh ``kexResult{H, K, HostKey, Signature, Hash, SessionID}``.

    Each field is a slice header ``(ptr, len, cap)``; ``Hash`` is a ``crypto.Hash``. K is
    already the encoded mpint (``marshalInt``), so its first 4 bytes equal its length - 4.
    """
    out = []
    for va, m in memory.finditer(_GO_KEXRESULT, 8, _GO_SCOUT, 8):
        q = [struct.unpack("<Q", g)[0] for g in m.groups()]
        h = _slice(memory, q[0], q[1], q[2], 64)
        k = _slice(memory, q[3], q[4], q[5], 1100)
        sid = _slice(memory, q[13], q[14], q[15], 64)
        if not (h and k and sid) or not ssh_kdf.is_encoded(k) or len(k) < 8:
            continue
        if not (high_entropy(h) and high_entropy(sid)):
            continue
        out.append(KexTuple("go-x/crypto/ssh", [k], h, sid, CRYPTO_HASH_IDS.get(q[12]),
                            {"kexResult": va, "K": q[3], "H": q[0], "session_id": q[13]},
                            locator="go:kexResult"))
    return out


def _pybytes_pattern(size):
    return re.compile(rb"(?s)(?=(.{8})(.{8})" + re.escape(struct.pack("<Q", size)) +
                      rb"(.{8})(.{%d})\x00)" % size)


_PY_BYTES = {size: _pybytes_pattern(size) for size in HASH_SIZES}
_PY_BYTES_SCOUT = {size: re.compile(rb"(?=" + re.escape(struct.pack("<Q", size)) + rb")")
                   for size in HASH_SIZES}
_PY_LONG_DIGITS = (9, 13, 18)   # 256-bit (x25519, P-256), P-384, P-521 shared secrets
_PY_LONG = {
    n: re.compile(rb"(?s)(?=(.{8})(.{8})(" + re.escape(struct.pack("<Q", n)) + rb"|" +
                  re.escape(struct.pack("<Q", n << 3)) + rb")((?:.{3}[\x00-\x3f]){%d}))" % n)
    for n in _PY_LONG_DIGITS
}


def _py_bytes_objects(memory):
    """``{type_ptr: [(va, data)]}`` of CPython bytes-object look-alikes of hash sizes."""
    found = {}
    for size, pattern in _PY_BYTES.items():
        for va, m in memory.finditer(pattern, 16, _PY_BYTES_SCOUT[size], 16):
            refcnt, type_ptr = struct.unpack("<QQ", m.group(1) + m.group(2))
            data = m.group(4)
            if 0 < refcnt < (1 << 32) and _pointer(type_ptr) and high_entropy(data):
                found.setdefault(type_ptr, []).append((va + 32, data))
    return found


def _py_long_values(memory):
    """``[(va, int)]`` of CPython int objects with 9/13/18 30-bit digits (3.11 and 3.12+)."""
    values = []
    for n, pattern in _PY_LONG.items():
        scout = re.compile(rb"(?=" + re.escape(struct.pack("<Q", n)) + rb"|" +
                           re.escape(struct.pack("<Q", n << 3)) + rb")")
        for va, m in memory.finditer(pattern, 16, scout, 16):
            refcnt, type_ptr = struct.unpack("<QQ", m.group(1) + m.group(2))
            if not (0 < refcnt < (1 << 32) and _pointer(type_ptr)):
                continue
            digits = struct.unpack("<%dI" % n, m.group(4))
            if digits[-1] == 0:
                continue
            value = 0
            for index, digit in enumerate(digits):
                value |= digit << (30 * index)
            if value.bit_length() >= 30 * (n - 1):
                values.append((va, value))
    return values


def find_python_kex(memory):
    """CPython (Paramiko ``Transport.K`` int, ``H``/``session_id`` bytes objects).

    The bytes type is the type pointer most of the hash-sized bytes look-alikes share.
    Every big int is a K candidate and every hash-sized bytes object an H candidate.
    """
    by_type = _py_bytes_objects(memory)
    if not by_type:
        return []
    bytes_type = max(by_type, key=lambda t: len(by_type[t]))
    hashes = []
    seen = set()
    for va, data in by_type[bytes_type]:
        if data not in seen:
            seen.add(data)
            hashes.append((va, data))
    longs = []
    seen_k = set()
    for va, value in _py_long_values(memory):
        if value not in seen_k:
            seen_k.add(value)
            longs.append((va, value))
    out = []
    for k_va, value in longs:
        k_options = [ssh_kdf.encode_mpint(value)]
        for h_va, h in hashes:
            out.append(KexTuple("python/paramiko", k_options, h, h, None,
                                {"K": k_va, "H": h_va}, locator="cpython:int+bytes"))
    return out


_LIBSSH_CRYPTO = re.compile(
    rb"(?s)(?=([\x14\x20\x30\x40]\x00{7})(.{8})([\x14\x20\x30\x40]\x00{7})(.{8})(.{48}))")
_LIBSSH_LABELS = ("encryptIV", "decryptIV", "decryptkey", "encryptkey", "encryptMAC",
                  "decryptMAC")


def _openssl_bignum(memory, ptr):
    """The value of an OpenSSL ``BIGNUM {d, top, dmax, neg, flags}`` at ``ptr``, or None."""
    raw = memory.read(ptr, 24) if _pointer(ptr) else None
    if raw is None:
        return None
    d, top, dmax, neg, flags = struct.unpack("<QiiiI", raw)
    if not (_pointer(d) and 3 <= top <= 130 and top <= dmax <= 4 * top + 8 and neg in (0, 1)
            and flags < 0x100):
        return None
    limbs = memory.read(d, 8 * top)
    if limbs is None:
        return None
    value = int.from_bytes(limbs, "little")
    return value if value.bit_length() > 64 * (top - 1) else None


LIBSSH_KEX_METHODS = 10          # SSH_KEX_METHODS: kex, hostkey, cipher c2s/s2c, mac c2s/s2c, ...
LIBSSH_METHODS_WINDOW = 0x400    # kex_methods[] follows server_kex/client_kex in the struct


def _libssh_methods(memory, va):
    """``[name]`` of a ``char *[SSH_KEX_METHODS]`` at ``va``, or None (any slot unreadable)."""
    names = []
    for slot in range(LIBSSH_KEX_METHODS):
        ptr = memory.qword(va + 8 * slot)
        name = memory.cstring(ptr, 128) if ptr and _pointer(ptr) else None
        if name is None:
            return None
        names.append(name)
    return names


def _is_negotiated_methods(names):
    """True for the ELECTED ``kex_methods``: one name per slot, known ciphers and MACs (the
    ``server_kex``/``client_kex`` offers hold comma lists, at least for the kex)."""
    if names is None or any("," in name for name in names[:6]):
        return False
    ciphers, macs = names[2:4], names[4:6]
    return (all(c in ssh_kdf.CIPHERS for c in ciphers)
            and all(ssh_kdf.mac_key_length(m) is not None or ssh_kdf.CIPHERS[c][3]
                    for c, m in zip(ciphers, macs)))


def find_libssh_negotiated(memory, va, window=LIBSSH_METHODS_WINDOW):
    """libssh ``ssh_crypto_struct.kex_methods`` (the elected algorithms, heap ``strdup``s)
    within ``window`` bytes after ``session_id_len`` at ``va``, as :class:`Negotiated`.

    Found by shape, not by offset (the members before it depend on the build): ten string
    pointers whose c2s/s2c cipher and MAC slots are single known names. None when absent
    or when two such arrays disagree.
    """
    found = set()
    for at in range(va, va + window, 8):
        names = _libssh_methods(memory, at)
        if _is_negotiated_methods(names):
            found.add(tuple(names[2:6]))
    if len(found) != 1:
        return None
    c2s, s2c, mac_c2s, mac_s2c = found.pop()
    return Negotiated("libssh", {"c2s": (c2s, mac_c2s), "s2c": (s2c, mac_s2c)})


def find_libssh_kex(memory, lookback=0x400):
    """libssh ``ssh_crypto_struct``: ``session_id_len, session_id, digest_len, secret_hash``
    followed by six key pointers; K is the ``shared_secret`` BIGNUM pointed to from the
    start of the struct (searched up to ``lookback`` bytes before ``session_id_len``)."""
    out = []
    for va, m in memory.finditer(_LIBSSH_CRYPTO, align=8):
        sid_len, sid_ptr, h_len, h_ptr = struct.unpack("<QQQQ", b"".join(m.groups()[:4]))
        key_ptrs = struct.unpack("<6Q", m.group(5))
        if sid_len != h_len or not all(_pointer(p) for p in (sid_ptr, h_ptr) + key_ptrs):
            continue
        sid, h = memory.read(sid_ptr, sid_len), memory.read(h_ptr, h_len)
        if not (sid and h and high_entropy(h)):
            continue
        trusted = []
        for label, ptr in zip(_LIBSSH_LABELS, key_ptrs):
            blob = memory.read(ptr, 64) or memory.read(ptr, 32) or memory.read(ptr, 16)
            if blob:
                trusted.append((label, ptr, blob))
        k_options = []
        for back in range(8, lookback + 8, 8):
            value = _openssl_bignum(memory, memory.qword(va - back) or 0)
            if value is not None:
                k_options.append(ssh_kdf.encode_mpint(value))
        if k_options:
            out.append(KexTuple("libssh", k_options, h, sid, None,
                                {"crypto": va, "H": h_ptr, "session_id": sid_ptr},
                                trusted, locator="libssh:ssh_crypto_struct",
                                negotiated=find_libssh_negotiated(memory, va)))
    return out


_WOLFSSH_SIZE = {size: re.compile(rb"(?=" + re.escape(struct.pack("<I", size)) + rb")")
                 for size in HASH_SIZES}
WOLFSSH_MAX_K_ARRAY = 2048


def find_wolfssh_kex(memory):
    """wolfSSH ``WOLFSSH`` (1.4.20, checked on a real capture)::

        byte h[64]; word32 hSz; byte k[...]; word32 kSz; byte sessionId[64]; word32 sessionIdSz;

    followed by the ``Keys`` structs holding the derived keys. Anchor: ``sessionIdSz`` ==
    ``hSz`` == L with the first L bytes of ``sessionId`` equal to ``h`` (first kex), ``h``
    at most ``WOLFSSH_MAX_K_ARRAY`` bytes before; K is ``k[:kSz]`` (raw magnitude).
    """
    out, seen = [], set()
    for size, pattern in _WOLFSSH_SIZE.items():
        for size_va, _m in memory.finditer(pattern, align=4):
            sid_va = size_va - 64
            sid = memory.read(sid_va, size)
            k_size = struct.unpack("<I", memory.read(sid_va - 4, 4) or b"\0" * 4)[0]
            if not sid or not 16 <= k_size <= WOLFSSH_MAX_K_ARRAY or not high_entropy(sid):
                continue
            window = memory.read(sid_va - 4 - WOLFSSH_MAX_K_ARRAY, WOLFSSH_MAX_K_ARRAY) or b""
            for at in _all_offsets(window, sid):
                h_va = sid_va - 4 - WOLFSSH_MAX_K_ARRAY + at
                if memory.read(h_va + 64, 4) != struct.pack("<I", size):
                    continue
                k_raw = memory.read(h_va + 68, k_size)
                if not k_raw or (h_va, sid_va) in seen or h_va + 68 + k_size > sid_va - 4:
                    continue
                seen.add((h_va, sid_va))
                out.append(KexTuple("wolfssh", [ssh_kdf.encode_mpint(k_raw)], sid, sid, None,
                                    {"h": h_va, "k": h_va + 68, "sessionId": sid_va},
                                    locator="wolfssh:WOLFSSH.h/k/sessionId"))
    return out


def _all_offsets(window, needle):
    position = window.find(needle)
    while position >= 0:
        yield position
        position = window.find(needle, position + 1)


_ENCODED_K = re.compile(rb"\x00\x00\x00(?:\x20|\x21\x00(?=[\x80-\xff])|\x40)")
_SSHBUF_SCOUT = re.compile(rb"(?=" + re.escape(struct.pack("<Q", SSHBUF_SIZE_MAX)) + rb")")
_SSHBUF = re.compile(rb"(?s)(?=(.{8})\1\x00{8}([\x14\x20\x30\x40]\x00{7})" +
                     re.escape(struct.pack("<Q", SSHBUF_SIZE_MAX)) + rb"(.{8}))")


def find_encoded_k(memory, limit=4096):
    """``[(va, encoded K)]``: length-prefixed 32/33/64-byte values (mpint or string K)."""
    out, seen = [], set()
    for va, m in memory.finditer(_ENCODED_K):
        length = struct.unpack(">I", m.group(0)[:4])[0]
        blob = memory.read(va, 4 + length)
        if blob is None or blob in seen or not high_entropy(blob[-32:]):
            continue
        if length == 0x20 and blob[4] == 0:   # not a canonical mpint, and no hash-K string
            continue
        seen.add(blob)
        out.append((va, blob))
        if len(out) >= limit:
            break
    return out


def find_sshbuf_hashes(memory):
    """``[(va, bytes)]``: OpenSSH ``struct sshbuf`` (d == cd, off 0, max_size 128 MiB)
    holding exactly a hash-sized value (``kex->session_id``)."""
    out = []
    for va, m in memory.finditer(_SSHBUF, 8, _SSHBUF_SCOUT, 32):
        d = struct.unpack("<Q", m.group(1))[0]
        size = struct.unpack("<Q", m.group(2))[0]
        alloc = struct.unpack("<Q", m.group(3))[0]
        if not (_pointer(d) and size <= alloc <= (1 << 20)):
            continue
        data = memory.read(d, size)
        if data and high_entropy(data):
            out.append((d, data))
    return out


def find_resident_k(memory, hashes):
    """Generic Tier A: an encoded K still resident, paired with every known H/session_id."""
    out = []
    for k_va, k in find_encoded_k(memory):
        for h_va, h in hashes:
            out.append(KexTuple("resident-K", [k], h, h, None, {"K": k_va, "H": h_va},
                                locator="generic:encoded-K+session_id"))
    return out


# --------------------------------------------------------------------------- proof sweep


def _needles(material):
    """8-byte probes (as ints) for a 64-byte derivation: halves at 0 and 32, both orders."""
    for offset in (0, 32):
        chunk = material[offset:offset + 8]
        yield struct.unpack("<Q", chunk)[0], offset, False
        # ssh_kdf.swap_words(chunk) for exactly two words, by slicing (this runs per probe)
        yield struct.unpack("<Q", chunk[3::-1] + chunk[7:3:-1])[0], offset, True


def _derivations(kex):
    """``[(hash, encoded K, {letter: 64 bytes})]`` for every hash/encoding option of a tuple."""
    hashes = [kex.hash_name] if kex.hash_name else [ssh_kdf.guess_hash(kex.exchange_hash)]
    out = []
    for hash_name in hashes:
        if not hash_name:
            continue
        for k_encoded in kex.k_options:
            out.append((hash_name, k_encoded, ssh_kdf.derive_all(
                k_encoded, kex.exchange_hash, kex.session_id, ssh_kdf.MAX_DERIVED, hash_name)))
    return out


def _sweep(memory, probes, chunk=1 << 22):
    """``{probe: [va]}`` for every probe int found at a 4-aligned VA (set intersection)."""
    hits = {}
    for start, data in memory.segments:
        for shift in (0, 4):
            for base in range(shift, len(data), chunk):
                block = data[base:base + chunk + 8]
                usable = (len(block) // 8) * 8
                if usable == 0:
                    continue
                words = set(struct.unpack("<%dQ" % (usable // 8), block[:usable]))
                for probe in words & probes:
                    raw = struct.pack("<Q", probe)
                    position = block.find(raw)
                    while 0 <= position < usable:
                        if position % 8 == 0:
                            va = start + base + position
                            if va % 4 == 0 and va not in hits.setdefault(probe, []):
                                hits[probe].append(va)
                        position = block.find(raw, position + 1)
    return hits


class Evidence(object):
    """Matches of one derivation: ``{letter: [(va, offset, length, swapped)]}``."""

    def __init__(self, kex, hash_name, k_encoded, derived):
        self.kex = kex
        self.hash_name = hash_name
        self.k_encoded = k_encoded
        self.derived = derived
        self.matches = {}

    def add(self, letter, va, offset, length, swapped):
        entries = self.matches.setdefault(letter, [])
        if all(e[0] != va for e in entries):
            entries.append((va, offset, length, swapped))

    @property
    def letters(self):
        return "".join(sorted(self.matches))


def prove(memory, tuples, max_combinations=MAX_COMBINATIONS):
    """Re-derive A..F for every tuple and find the derived keys in ``memory``.

    Returns ``[Evidence]`` with at least one match, best first. The final judgement is
    re-done by :func:`ssh_kdf.matched_letters` on the bytes actually read back, i.e. the
    exact rule of the ``ssh-kdf-consistency`` oracle.
    """
    unique, seen = [], set()
    for kex in tuples:
        if kex.key() not in seen:
            seen.add(kex.key())
            unique.append(kex)
    probes, table, evidences = set(), {}, []
    for kex in unique[:max_combinations]:
        for hash_name, k_encoded, derived in _derivations(kex):
            evidence = Evidence(kex, hash_name, k_encoded, derived)
            evidences.append(evidence)
            for letter, material in derived.items():
                for probe, offset, swapped in _needles(material):
                    probes.add(probe)
                    table.setdefault(probe, []).append((evidence, letter, offset, swapped))
    if not probes:
        return []
    for probe, vas in _sweep(memory, probes).items():
        for evidence, letter, offset, swapped in table[probe]:
            for va in vas:
                _extend(memory, evidence, letter, offset, swapped, va)
    _near_structs(memory, evidences)
    found = [e for e in evidences if e.matches]
    found.sort(key=lambda e: (-len(e.matches), e.kex.implementation))
    return found


def _extend(memory, evidence, letter, offset, swapped, va):
    """Record the match at ``va`` if at least ``MIN_MATCH`` bytes agree."""
    material = evidence.derived[letter][offset:]
    window = memory.read(va, len(material)) or memory.read(va, 32) or b""
    view = ssh_kdf.swap_words(window) if swapped else window
    length = ssh_kdf.match_length(material, view)
    if swapped:
        length -= length % 4
    if length >= ssh_kdf.MIN_MATCH:
        evidence.add(letter, va, offset, length, swapped)


NEAR_STRUCT = 0x2000
WINDOW_SCAN_NEEDLES = 256   # from this many needles per window, one positional pass is cheaper


def _anchor_window(memory, anchor):
    """``(base va, bytes)`` of the widest readable window around ``anchor``, or ``None``."""
    start = max(0, anchor - NEAR_STRUCT)
    for span in (2 * NEAR_STRUCT, NEAR_STRUCT, NEAR_STRUCT // 4):
        window = memory.read(start, span)
        if window:
            return start, window
        window = memory.read(anchor, span)
        if window:
            return anchor, window
    return None


def _near_structs(memory, evidences):
    """Unaligned search right around the struct each tuple came from: packed structs (wolfSSH
    ``Keys``) keep keys at odd offsets that the aligned sweep does not visit.

    Each anchor's window is read once and shared by every evidence that names it (Paramiko's
    K x H cross product repeats the same few hundred anchors across thousands of tuples).
    """
    by_anchor = {}
    for evidence in evidences:
        for anchor in set(evidence.kex.where.values()):
            by_anchor.setdefault(anchor, []).append(evidence)
    for anchor, sharing in by_anchor.items():
        found = _anchor_window(memory, anchor)
        if found is None:
            continue
        base, window = found
        needles = {}   # 12-byte prefix -> [(evidence, letter, offset)]
        for evidence in sharing:
            for letter, material in evidence.derived.items():
                for offset in (0, 32):
                    needles.setdefault(material[offset:offset + ssh_kdf.MIN_MATCH], []).append(
                        (evidence, letter, offset))
        for needle, at in _window_hits(window, needles):
            for evidence, letter, offset in needles[needle]:
                _extend(memory, evidence, letter, offset, False, base + at)


def _window_hits(window, needles):
    """``(needle, position)`` of every occurrence of every needle (all ``MIN_MATCH`` long).

    Few needles: one ``find`` scan each. Many: one pass over the window's positions with a
    dict lookup, which is cheaper than hundreds of scans of the same window.
    """
    if len(needles) < WINDOW_SCAN_NEEDLES:
        for needle in needles:
            for at in _all_offsets(window, needle):
                yield needle, at
        return
    width = ssh_kdf.MIN_MATCH
    for at in range(len(window) - width + 1):
        candidate = window[at:at + width]
        if candidate in needles:
            yield candidate, at


def verdict(evidence, memory):
    """``(proven, letters, detail)`` -- the oracle's rule on bytes read back from memory."""
    blobs = []
    for letter, entries in evidence.matches.items():
        for va, offset, length, swapped in entries:
            raw = memory.read(va, length)
            if raw:
                blobs.append(raw)
    letters = ssh_kdf.matched_letters(evidence.derived, blobs)
    status = ssh_kdf.proof_status(len(letters), trusted=False)
    return status, "".join(sorted(letters))


# --------------------------------------------------------------------------- Tier B (OpenSSH)


def _sshenc_pattern():
    alternatives = []
    for key_len, iv_len, block, _auth in set(ssh_kdf.CIPHERS.values()):
        alternatives.append(re.escape(struct.pack("<III", key_len, iv_len, block)))
    return re.compile(rb"(?s)(?=(.{8})(.{8})([\x00\x01]\x00{3})(" + b"|".join(alternatives) +
                      rb")(.{8})(.{8}))")


_SSHENC = _sshenc_pattern()
_SSHENC_SCOUT = re.compile(rb"(?=[\x00\x01]\x00{3}(?:" + b"|".join(
    re.escape(struct.pack("<III", k, i, b)) for k, i, b, _a in set(ssh_kdf.CIPHERS.values())) +
    rb"))")


class SshEnc(object):
    """One validated OpenSSH ``struct newkeys`` (its ``sshenc`` and ``sshmac``)."""

    def __init__(self, va, name, key, iv, mac_name, mac_key, key_ptr, cipher_checked):
        self.va, self.name, self.key, self.iv = va, name, key, iv
        self.mac_name, self.mac_key, self.key_ptr = mac_name, mac_key, key_ptr
        self.cipher_checked = cipher_checked


def _sshmac(memory, va):
    """``struct sshmac`` right after ``sshenc`` in ``struct newkeys`` (name, key)."""
    raw = memory.read(va, 32)
    if raw is None:
        return None, b""
    name_ptr, enabled, mac_len, key_ptr, key_len = struct.unpack("<QiIQI4x", raw)
    name = memory.cstring(name_ptr) if _pointer(name_ptr) else None
    expected = ssh_kdf.mac_key_length(name)
    if not name or expected is None or key_len != expected or not _pointer(key_ptr):
        return None, b""
    return name, memory.read(key_ptr, key_len) or b""


def find_openssh_newkeys(memory):
    """``[SshEnc]`` -- validated OpenSSH ``struct newkeys`` (sshenc + sshmac)."""
    out = []
    for va, m in memory.finditer(_SSHENC, 8, _SSHENC_SCOUT, 16):
        name_ptr, cipher_ptr = struct.unpack("<QQ", m.group(1) + m.group(2))
        key_len, iv_len, block = struct.unpack("<III", m.group(4))
        key_ptr, iv_ptr = struct.unpack("<QQ", m.group(5) + m.group(6))
        name = memory.cstring(name_ptr) if _pointer(name_ptr) else None
        if not name or ssh_kdf.CIPHERS.get(name, (None,))[:3] != (key_len, iv_len, block):
            continue
        if not _pointer(cipher_ptr):
            continue
        # ``struct sshcipher`` sits in the binary's RELRO (read-only) data, which a scan of
        # writable mappings does not hold: check it whenever it is readable.
        cipher = memory.read(cipher_ptr, 24)
        if cipher is not None:
            c_name, c_block, c_key, c_iv = struct.unpack("<QIII4x", cipher)
            if (memory.cstring(c_name) != name
                    or (c_block, c_key, c_iv) != (block, key_len, iv_len)):
                continue
        key = memory.read(key_ptr, key_len) if _pointer(key_ptr) else None
        if not key or not high_entropy(key[:32]):
            continue
        iv = (memory.read(iv_ptr, iv_len) or b"") if iv_len and _pointer(iv_ptr) else b""
        mac_name, mac_key = _sshmac(memory, va + 48)
        out.append(SshEnc(va, name, key, iv, mac_name, mac_key, key_ptr, cipher is not None))
    return out


def openssh_modes(memory, encs):
    """``{sshenc va: "in"|"out"}`` from ``newkeys[MODE_MAX]`` (two adjacent pointers)."""
    addresses = {e.va for e in encs}
    modes = {}
    for enc in encs:
        for slot_va in memory.find_all(struct.pack("<Q", enc.va), limit=16):
            if slot_va % 8:
                continue
            after, before = memory.qword(slot_va + 8), memory.qword(slot_va - 8)
            if after in addresses and after != enc.va:
                modes.setdefault(enc.va, "in")
                modes.setdefault(after, "out")
            elif before in addresses and before != enc.va:
                modes.setdefault(enc.va, "out")
                modes.setdefault(before, "in")
    return modes


# --------------------------------------------------------------------------- Tier C


def find_chacha_pairs(memory):
    """``[(va, 64-byte key, layout)]``: two adjacent ChaCha20 states whose keys form the
    chacha20-poly1305@openssh.com key (main ``K_2`` first, header ``K_1`` second).

    Layouts: libtomcrypt ``chacha_state`` (152 bytes: input[16], kstream[64], ksleft,
    ivlen, rounds == 20; Dropbear) and the 64-byte ``chacha_ctx`` of OpenSSH's own chacha.
    """
    out = []
    for va in memory.find_all(CHACHA_CONSTANTS, limit=4096):
        for layout, stride in (("libtomcrypt", 152), ("openssh-chacha_ctx", 64)):
            first, second = memory.read(va, 64), memory.read(va + stride, 64)
            if not (first and second and second.startswith(CHACHA_CONSTANTS)):
                continue
            if layout == "libtomcrypt":
                tail = memory.read(va + 128, 24) or b""
                tail2 = memory.read(va + stride + 128, 24) or b""
                if len(tail) < 24 or len(tail2) < 24:
                    continue
                ksleft, ivlen, rounds = struct.unpack("<QQi4x", tail)
                if rounds != 20 or ivlen not in (8, 12) or ksleft > 64:
                    continue
                if struct.unpack("<QQi4x", tail2)[2] != 20:
                    continue
            key = first[16:48] + second[16:48]
            if high_entropy(key[:32]) and high_entropy(key[32:]):
                out.append((va, key, layout))
                break
    return out


_AES_ZERO_PATTERNS = {
    # Z = d[j+20] ^ d[j+16] ^ d[j+4]: w5..w7 zero, w8 not, ... up to w43 (AES-128)
    4: re.compile(rb"(?s)(?=(?:\x00{12}(?!\x00{4}).{4}){9}\x00{12})"),
    # Z = d[j+24] ^ d[j+20] ^ d[j]: w6 not zero, w7..w11 zero, ... (AES-192)
    6: re.compile(rb"(?s)(?=(?:(?!\x00{4}).{4}\x00{20}){7})"),
    # Z = d[j+32] ^ d[j+28] ^ d[j]: w8 not zero, w9..w11 zero, w12 not, ... (AES-256)
    8: re.compile(rb"(?s)(?=(?:(?!\x00{4}).{4}\x00{12}){6})"),
}


def _aes_relation(number, nk):
    """Byte j of the result is zero where word ``w[j/4 + k]`` obeys the linear rule."""
    if nk == 4:
        return (number >> 160) ^ (number >> 128) ^ (number >> 32)
    return (number >> (32 * nk)) ^ (number >> (32 * (nk - 1))) ^ number


AES_WINDOW = 16 << 20
AES_WINDOW_OVERLAP = 240     # the longest schedule (AES-256): every hit is checked in-window


def _aes_zero_hits(data, nk):
    """Offsets in ``data`` where the ``nk`` zero pattern of :func:`_aes_relation` starts.

    Worked in ``AES_WINDOW`` slices that overlap by ``AES_WINDOW_OVERLAP`` bytes (a whole
    segment as one big integer costs several times its size in memory). A hit is kept only
    in its own window's first ``AES_WINDOW`` bytes, where every byte the pattern reads is
    real data, so the offsets are exactly those of the whole-segment computation.
    """
    for base in range(0, len(data), AES_WINDOW):
        window = data[base:base + AES_WINDOW + AES_WINDOW_OVERLAP]
        number = int.from_bytes(window, "little")
        zbytes = _aes_relation(number, nk).to_bytes(len(window), "little")
        for m in _AES_ZERO_PATTERNS[nk].finditer(zbytes):
            if m.start() >= AES_WINDOW:
                break
            yield base + m.start()


def find_aes_schedules(memory, limit=256):
    """``[(va, key, byteorder)]``: AES encryption key schedules that re-expand exactly.

    Prefilter: the linear words of a schedule satisfy ``w[i] = w[i-Nk] ^ w[i-1]``, which is
    byte-wise, so it holds in either word byte order. XOR-ing the memory with two shifted
    copies of itself turns every schedule into a fixed zero pattern a regex finds at C
    speed; each hit is then re-expanded with ``aes.expand_key`` and compared byte for byte.
    """
    out, seen = [], set()
    for start, data in memory.segments:
        for nk in (4, 6, 8):
            key_len = 4 * nk
            for pos in _aes_zero_hits(data, nk):
                if (start + pos) % 4:
                    continue
                for byteorder in ("little", "big"):
                    key = data[pos:pos + key_len]
                    if byteorder == "big":
                        key = ssh_kdf.swap_words(key)
                    if len(key) != key_len or key in seen or not high_entropy(key):
                        continue
                    schedule = aes.expand_key(key)
                    stored = schedule if byteorder == "little" else ssh_kdf.swap_words(schedule)
                    if data[pos:pos + len(stored)] == stored:
                        seen.add(key)
                        out.append((start + pos, key, byteorder))
                if len(out) >= limit:
                    return out
    return out


# --------------------------------------------------------------------------- analysis


def _libtomcrypt_process(process_name):
    """Dropbear (server or dbclient) keeps AES keys only as libtomcrypt schedules."""
    name = (process_name or "").rsplit("/", 1)[-1]
    return name.startswith("dropbear") or name == "dbclient"


def role_of(process_name):
    name = (process_name or "").rsplit("/", 1)[-1]
    if name in SERVER_NAMES or name.startswith("sshd"):
        return "server"
    if name in CLIENT_NAMES:
        return "client"
    return None


def _direction(mode, role):
    """``newkeys`` mode (in/out) or Dropbear ``key_context`` half (recv/trans) -> c2s/s2c
    for a known role, else the raw mode."""
    if role == "client":
        return {"out": "c2s", "in": "s2c", "trans": "c2s", "recv": "s2c"}.get(mode, mode or "?")
    if role == "server":
        return {"in": "c2s", "out": "s2c", "recv": "c2s", "trans": "s2c"}.get(mode, mode or "?")
    return mode or "?"


def dropbear_modes(pairs):
    """``{va: "recv"|"trans"}`` when exactly two libtomcrypt pairs exist: Dropbear's
    ``struct key_context`` holds ``recv`` before ``trans`` (same struct size apart)."""
    tomcrypt = sorted(va for va, _key, layout in pairs if layout == "libtomcrypt")
    if len(tomcrypt) != 2:
        return {}
    return {tomcrypt[0]: "recv", tomcrypt[1]: "trans"}


AES_KEY_LENGTHS = (32, 24, 16)
IV_LENGTHS = {"gcm": 12, "ctr|cbc": 16}
MAC_KEY_LENGTHS = ((64, "hmac-sha2-512"), (32, "hmac-sha2-256"), (20, "hmac-sha1"),
                   (16, "hmac-md5|umac"))


def _aes_schedule_resident(memory, key):
    """True when the rest of ``key``'s AES schedule (round key after the key) is in memory."""
    schedule = aes.expand_key(key)
    tail = schedule[len(key):len(key) + 16]
    return bool(memory.find_all(tail, limit=1) or
                memory.find_all(ssh_kdf.swap_words(schedule)[len(key):len(key) + 16], limit=1))


def _matched_lengths(evidence):
    """``{letter: bytes of derived material found}`` (an upper bound of the real length)."""
    return {letter: max(e[2] + e[1] for e in entries)
            for letter, entries in evidence.matches.items()}


def _resolve_lengths(memory, evidence):
    """``(cipher, mac, {letter: real length})`` for one proven derivation.

    A matched length is only an UPPER bound: implementations keep keys in buffers sized
    for the hash output (libssh derives 32-byte IVs and uses 16), so the match runs on.
    The real lengths come from the cipher: chacha20-poly1305 (a 32-byte half found, or
    >= 64 bytes) takes 64-byte keys and no IV/MAC; an AES key length is the one whose key
    schedule is resident (checked first, so a 64-byte buffer holding an AES key is not taken
    for chacha; else the largest standard length that matched); the AES mode is GCM (IV 12)
    when no MAC key (E/F) is found or the IV match is shorter than 16, else CTR/CBC (IV
    16); MAC keys take the largest HMAC key length that matched. Go, for one, keeps the
    whole 32-byte digest behind a 12-byte GCM nonce, so lengths never come from the match.
    """
    matched = _matched_lengths(evidence)
    half = any(e[1] == 32 for es in evidence.matches.values() for e in es)
    key_match = max(matched.get("C", 0), matched.get("D", 0))
    lengths = {}
    options = [n for n in AES_KEY_LENGTHS if n <= key_match] or [key_match]
    scheduled = next((n for n in options for c in "CD" if c in matched and n >= 16
                      and _aes_schedule_resident(memory, evidence.derived[c][:n])), None)
    if scheduled is None and (half or key_match >= 64):
        cipher, mac = "chacha20-poly1305@openssh.com", "<implicit>"
        lengths.update({c: 64 for c in "CD" if c in matched})
    else:
        key_len = scheduled or options[0]
        iv_match = max(matched.get("A", 0), matched.get("B", 0))
        # AES-GCM is an AEAD: no MAC key is ever derived. A non-AEAD AES mode always comes
        # with an HMAC key (E/F), which every implementation keeps for the session.
        has_mac = "E" in matched or "F" in matched
        mode = "gcm" if (iv_match and iv_match < 16) or not has_mac else "ctr|cbc"
        cipher = "aes%d-%s" % (key_len * 8, mode)
        mac = "<implicit>" if mode == "gcm" else "?"
        lengths.update({c: key_len for c in "CD" if c in matched})
        lengths.update({c: IV_LENGTHS[mode] for c in "AB" if c in matched})
    mac_match = max(matched.get("E", 0), matched.get("F", 0))
    for length, name in MAC_KEY_LENGTHS:
        if mac_match >= length:
            mac = name
            lengths.update({c: length for c in "EF" if c in matched})
            break
    for letter, length in matched.items():   # never longer than what was found
        lengths[letter] = min(lengths.get(letter, length), length)
    return cipher, mac, lengths


def openssh_negotiated(evidence, encs):
    """:class:`Negotiated` from the OpenSSH ``sshenc`` records whose key buffer IS a matched
    C/D key (the match starts at ``sshenc.key``): that record's ``name``/``sshmac`` are the
    algorithms of the letter's direction. None when no record is bound."""
    by_key = {enc.key_ptr: enc for enc in encs}
    by_direction = {}
    for letter in "CD":
        for va, offset, _length, swapped in evidence.matches.get(letter, ()):
            enc = None if swapped else by_key.get(va - offset)
            if enc is not None:
                by_direction[ssh_kdf.LETTER_ROLE[letter][1]] = (enc.name, enc.mac_name)
    return Negotiated("openssh", by_direction) if by_direction else None


def _negotiated_length(kind, cipher, mac):
    """``(algorithm name, length)`` of a key/iv/mac row from negotiated names, or None when
    they do not fix it (unknown name, an AEAD's MAC key, a cipher without IV)."""
    spec = ssh_kdf.CIPHERS.get(cipher)
    if spec is None:
        return None
    key_len, iv_len, _block, tag = spec
    if kind == "key":
        return cipher, key_len
    if kind == "iv":
        return (cipher, iv_len) if iv_len else None
    length = None if tag else ssh_kdf.mac_key_length(mac)
    return (mac, length) if length else None


def resolve_algorithms(memory, evidence, negotiated):
    """``({letter: (algorithm name, length)}, source)`` for one proven derivation.

    The negotiated algorithms an implementation stored win; letters they do not fix fall
    back to :func:`_resolve_lengths` (inference from the cipher state in memory). A length
    is never longer than what was found. ``source`` says which: ``negotiated(<where>)``,
    ``inferred``, or both with their letters.
    """
    matched = _matched_lengths(evidence)
    chosen = {}
    by_direction = negotiated.by_direction if negotiated is not None else {}
    for letter in matched:
        kind, direction = ssh_kdf.LETTER_ROLE[letter]
        pair = by_direction.get(direction)
        algorithm = _negotiated_length(kind, *pair) if pair else None
        if algorithm is not None:
            chosen[letter] = (algorithm[0], min(algorithm[1], matched[letter]))
    inferred = sorted(set(matched) - set(chosen))
    if inferred:
        cipher, mac, lengths = _resolve_lengths(memory, evidence)
        for letter in inferred:
            kind = ssh_kdf.LETTER_ROLE[letter][0]
            chosen[letter] = (mac if kind == "mac" else cipher, lengths[letter])
    if not inferred:
        source = "negotiated(%s)" % negotiated.source
    elif len(inferred) == len(matched):
        source = "inferred"
    else:
        source = "negotiated(%s) for %s, inferred for %s" % (
            negotiated.source, "".join(sorted(set(matched) - set(inferred))),
            "".join(inferred))
    return chosen, source


class Analysis(object):
    """Everything found in one process, as rows."""

    def __init__(self, rows, tuples_tried, evidence, stats):
        self.rows = rows
        self.tuples_tried = tuples_tried
        self.evidence = evidence
        self.stats = stats


def _locate(memory, implementation):
    """Every Tier A tuple candidate, honouring an implementation filter."""
    want = (implementation or "auto").lower()
    tuples, stats = [], {}

    def run(name, finder, *args):
        if want in ("auto", name):
            found = finder(memory, *args)
            stats[name] = len(found)
            tuples.extend(found)

    run("go", find_go_kex_results)
    run("libssh", find_libssh_kex)
    run("wolfssh", find_wolfssh_kex)
    run("paramiko", find_python_kex)
    if want in ("auto", "openssh", "resident"):
        hashes = find_sshbuf_hashes(memory)
        hashes += [(t.where.get("H", 0), t.exchange_hash) for t in tuples
                   if t.locator != "cpython:int+bytes"][:64]
        found = find_resident_k(memory, hashes)
        stats["resident-K"] = len(found)
        stats["sshbuf-H"] = len(hashes)
        tuples.extend(found)
    return tuples, stats


def _tier_a_rows(memory, evidences, encs=()):
    rows, proven_keys = [], set()
    used = set()
    for evidence in evidences:
        status, letters = verdict(evidence, memory)
        kex = evidence.kex
        if status != "proven":
            continue
        signature = kex.key()
        if signature in used:
            continue
        used.add(signature)
        negotiated = kex.negotiated or openssh_negotiated(evidence, encs)
        algorithms, source = resolve_algorithms(memory, evidence, negotiated)
        detail = ("tier A: keys %s re-derived (RFC 4253, %s, encoded K %d bytes) from "
                  "K/H/session_id at %s; lengths: %s"
                  % (letters, evidence.hash_name, len(evidence.k_encoded),
                     ", ".join("%s 0x%x" % kv for kv in sorted(kex.where.items())), source))
        for letter in sorted(evidence.matches):
            kind, direction = ssh_kdf.LETTER_ROLE[letter]
            name, length = algorithms[letter]
            key = evidence.derived[letter][:length]
            addresses = [entry[0] for entry in evidence.matches[letter]]
            rows.append(KeyRow(kex.implementation, "A", direction, kind, name, key, addresses,
                               PROVEN, detail, letter, kex.locator))
            proven_keys.add(key[:16])
            for entry in evidence.matches[letter]:
                if entry[1] == 32:
                    proven_keys.add(evidence.derived[letter][32:48])
    return rows, proven_keys


def _trusted_rejections(memory, tuples, evidences):
    """Tier A ``rejected`` rows: trusted structs whose own keys match NO derived key."""
    matched = {e.kex.key() for e in evidences}
    rows = []
    for kex in tuples:
        if not kex.trusted_found or kex.key() in matched:
            continue
        blobs = [blob for _, _, blob in kex.trusted_found]
        any_letters = False
        for hash_name, k_encoded, derived in _derivations(kex):
            if ssh_kdf.matched_letters(derived, blobs):
                any_letters = True
        if any_letters:
            continue
        label, va, blob = kex.trusted_found[0]
        rows.append(KeyRow(kex.implementation, "A", "?", "key", "?", blob[:32], [va], REJECTED,
                           "tier A: K/H/session_id from %s do not derive the struct's own keys"
                           % kex.locator, "", kex.locator))
    return rows


def _tier_b_rows(memory, role, proven_keys, stats, encs=None):
    """Tier B: validated OpenSSH ``newkeys``/``sshenc`` whose key no Tier A row proved."""
    rows = []
    if encs is None:
        encs = find_openssh_newkeys(memory)
    stats["openssh-newkeys"] = len(encs)
    modes = openssh_modes(memory, encs)
    for enc in encs:
        if enc.key[:16] in proven_keys:
            continue
        direction = _direction(modes.get(enc.va), role)
        halves = ""
        if enc.name.startswith("chacha20"):
            again = [len(memory.find_all(enc.key[i:i + 32], limit=3)) > 1 for i in (0, 32)]
            halves = "; both 32-byte halves also resident elsewhere" if all(again) else ""
        detail = ("tier B: OpenSSH newkeys/sshenc at 0x%x (%s, key_len %d, iv_len %d%s) "
                  "consistent; K not resident, no KDF proof%s"
                  % (enc.va, enc.name, len(enc.key), len(enc.iv),
                     ", sshcipher checked" if enc.cipher_checked else "", halves))
        rows.append(KeyRow("openssh", "B", direction, "key", enc.name, enc.key,
                           [enc.key_ptr], UNVERIFIED, detail, "", "openssh:newkeys"))
        if enc.iv:
            rows.append(KeyRow("openssh", "B", direction, "iv", enc.name, enc.iv,
                               [], UNVERIFIED, detail, "", "openssh:newkeys"))
        if enc.mac_key:
            rows.append(KeyRow("openssh", "B", direction, "mac", enc.mac_name,
                               enc.mac_key, [], UNVERIFIED, detail, "", "openssh:newkeys"))
    return rows


def _tier_c_chacha_rows(memory, role, proven_keys, tier_b, stats):
    """Tier C: ChaCha20 state pairs not already a Tier A/B key."""
    rows = []
    pairs = find_chacha_pairs(memory)
    stats["chacha-pairs"] = len(pairs)
    modes = dropbear_modes(pairs)
    for va, key, layout in pairs:
        if key[:16] in proven_keys or any(r.key[:32] == key[:32] for r in tier_b):
            continue
        impl = "dropbear" if layout == "libtomcrypt" else "openssh(no-openssl)"
        mode = modes.get(va)
        rows.append(KeyRow(impl, "C", _direction(mode, role), "key",
                           "chacha20-poly1305@openssh.com", key, [va], UNVERIFIED,
                           "tier C: %s ChaCha20 state pair at 0x%x (rounds 20) re-expands "
                           "to this 64-byte key%s; no KDF proof"
                           % (layout, va, (", key_context.%s" % mode) if mode else ""),
                           "", "chacha-state-pair"))
    return rows


def _tier_c_aes_rows(memory, proven_keys, earlier, stats):
    """Tier C: AES key schedules whose key is no ``earlier`` (Tier A/B) row's key."""
    rows = []
    schedules = find_aes_schedules(memory)
    stats["aes-schedules"] = len(schedules)
    for va, key, byteorder in schedules:
        if key[:16] in proven_keys or any(r.key[:len(key)] == key for r in earlier):
            continue
        rows.append(KeyRow("?", "C", "?", "key", "aes%d" % (len(key) * 8), key, [va],
                           UNVERIFIED, "tier C: AES key schedule at 0x%x (%s-endian "
                           "words) re-expands from this key; not bound to SSH"
                           % (va, byteorder), "", "aes-schedule"))
    return rows


def analyze(memory, process_name=None, implementation="auto", show_unbound=False):
    """Analyse one process's memory; returns an :class:`Analysis`."""
    role = role_of(process_name)
    tuples, stats = _locate(memory, implementation)
    evidences = prove(memory, tuples)
    want = (implementation or "auto").lower()
    # OpenSSH sshenc records: Tier B rows, and the negotiated cipher of a Tier A proof
    encs = find_openssh_newkeys(memory) if want in ("auto", "openssh") else []
    rows, proven_keys = _tier_a_rows(memory, evidences, encs)
    rows += _trusted_rejections(memory, tuples, evidences)
    tier_b = []
    if want in ("auto", "openssh"):
        tier_b = _tier_b_rows(memory, role, proven_keys, stats, encs)
    rows += tier_b
    tier_c = []
    if want in ("auto", "dropbear", "libssh2", "openssh"):
        tier_c = _tier_c_chacha_rows(memory, role, proven_keys, tier_b, stats)
        if show_unbound or want in ("dropbear", "libssh2") or _libtomcrypt_process(process_name):
            tier_c += _tier_c_aes_rows(memory, proven_keys, rows, stats)
    rows += tier_c
    stats["tuples"] = len(tuples)
    return Analysis(rows, len(tuples), evidences, stats)


def openssh_newkeys_lines(rows, timestamp=0):
    """KeyLifespan / OpenSSH keylog-patch lines: ``<ts> NEWKEYS MODE IN|OUT CIPHER <name>
    KEY <hex> IV <hex|unknown>`` -- one per direction with a cipher key."""
    lines = []
    by_direction = {}
    for row in rows:
        if row.proven == REJECTED:
            continue
        by_direction.setdefault(row.direction, {})[row.kind] = row
    for direction, kinds in sorted(by_direction.items()):
        key = kinds.get("key")
        if key is None:
            continue
        iv = kinds.get("iv")
        mode = {"c2s": "OUT", "s2c": "IN", "out": "OUT", "in": "IN"}.get(direction, "UNKNOWN")
        lines.append("%d NEWKEYS MODE %s CIPHER %s KEY %s IV %s" % (
            timestamp, mode, key.cipher, key.key.hex(), iv.key.hex() if iv else "unknown"))
    return lines

