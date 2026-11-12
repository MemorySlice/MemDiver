"""SSH session-key oracle: RFC 4253 key derivation checked against the same memory.

The candidate is an SSH shared secret ``K`` found in a process. The context carries the
exchange hash ``H`` and ``session_id`` found next to it, plus the keys/IVs/MAC keys found
in the SAME memory (``ctx["found"]``). The oracle derives the six RFC 4253 section 7.2
keys A..F from (K, H, session_id) and counts how many of them are among the found keys:

* ``proven``   -- at least TWO distinct derived keys (letters) are found. Each match is a
  >= 96-bit prefix of an independent SHA-2 output sitting somewhere else in memory, so
  two of them cannot happen by chance: (K, H, session_id) and those keys belong to the
  session. Nothing outside memory is involved (no capture file, no traffic).
* ``rejected`` -- NO derived key matches although ``ctx["trusted"]`` says the found keys
  are certainly this session's keys (read from the same implementation structure as K):
  then K (or H/session_id) is not the session's.
* ``error``    -- anything else, including exactly ONE match ("inconclusive": reported in
  ``detail``, never promoted to a proof) and malformed input.

Parameters (``build_oracle(params, sample)``, all optional): ``hash`` (``sha1``, ``sha256``,
``sha384``, ``sha512``; default: from the size of H), ``k_encoding`` (``mpint``,
``string``, ``encoded`` or ``auto`` = try mpint then string; ``encoded`` = the candidate
already carries its 4-byte length), ``kex`` (a kex method name, sets both), ``min_match``
(bytes, default 12). The sample is optional: :func:`make_sample` packs the same
parameters, so a generated plugin can pin them; it never carries key material.

The derivation itself lives in the stdlib-only primitive ``ssh_kdf``
(``vol3plugins/linux/secrets/ssh_kdf.py``, bound by the loader, see
``REQUIRES_PRIMITIVES``); without it ``verify`` returns an ``error`` verdict.
"""
import json

KIND = "ssh-kdf-consistency"
# The candidate is the shared secret K: 32 bytes for curve25519 (raw), 33-37 as an encoded
# mpint, 64 for the sntrup761/mlkem hybrids (string), up to 1028 for an 8192-bit DH group.
CANDIDATE_LENGTHS = (32, 33, 36, 37, 64, 68, 128, 132, 256, 260, 512, 516, 1024, 1028)
# Measured per verify() of a WRONG candidate, auto encoding (two derivations of six
# letters), four found keys, CPython 3.11.9 arm64 (best of 3 x 5000): sha256 31 us,
# sha512 33 us. Rounded up.
COST_US = 40
SAMPLE_KIND = ("none needed: memory self-consistency (H, session_id and the found keys come "
               "from the same memory); an optional sample only pins hash / K encoding")
REQUIRES_PRIMITIVES = ("ssh_kdf",)
SAMPLE_MAGIC = b"MDSSHKDF1"
SAMPLE_MAX_BYTES = 8192
HASHES = ("sha1", "sha256", "sha384", "sha512")
ENCODINGS = ("auto", "mpint", "string", "encoded")


def make_sample(hash_name=None, k_encoding=None, kex=None):
    """Pack the optional parameters ``hash`` / ``k_encoding`` / ``kex`` (no key material)."""
    meta = {k: v for k, v in (("hash", hash_name), ("k_encoding", k_encoding), ("kex", kex))
            if v}
    blob = SAMPLE_MAGIC + json.dumps(meta, sort_keys=True).encode("utf-8")
    if len(blob) > SAMPLE_MAX_BYTES:
        raise ValueError("sample too large")
    return blob


def parse_sample(sample):
    """The parameter dict packed by :func:`make_sample` (empty for an empty sample)."""
    if not sample:
        return {}
    sample = bytes(sample)
    if not sample.startswith(SAMPLE_MAGIC):
        raise ValueError("not an ssh-kdf-consistency sample (bad magic)")
    try:
        meta = json.loads(sample[len(SAMPLE_MAGIC):].decode("utf-8"))
    except ValueError as exc:
        raise ValueError("malformed ssh-kdf-consistency sample: %s" % exc)
    if not isinstance(meta, dict):
        raise ValueError("malformed ssh-kdf-consistency sample: not an object")
    return meta


def build_oracle(params, sample):
    """Build a verifier; ``params`` override what the sample pins."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    merged = dict(parse_sample(sample))
    merged.update({k: v for k, v in params.items() if v is not None})
    return SshKdfOracle(merged)


def _primitive():
    return globals().get("ssh_kdf")


class SshKdfOracle:
    """Verifies a shared secret K by re-deriving the session keys found in memory."""

    def __init__(self, params):
        kdf = _primitive()
        kex = params.get("kex")
        hash_name = params.get("hash") or (kdf.kex_hash(kex) if (kex and kdf) else None)
        if hash_name is not None and hash_name not in HASHES:
            raise ValueError("hash must be one of %s, not %r" % (HASHES, hash_name))
        encoding = params.get("k_encoding") or (
            kdf.kex_k_encoding(kex) if (kex and kdf) else "auto")
        if encoding not in ENCODINGS:
            raise ValueError("k_encoding must be one of %s, not %r" % (ENCODINGS, encoding))
        self.hash_name = hash_name
        self.k_encoding = encoding
        self.min_match = int(params.get("min_match", 12))
        if self.min_match < 8:
            raise ValueError("min_match below 8 bytes is not a proof")
        self.candidate_lengths = CANDIDATE_LENGTHS

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises."""
        try:
            return self._verify(candidate, ctx or {})
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", "verify failed: %r" % (exc,))

    def _encodings(self, kdf, candidate):
        if self.k_encoding != "auto":
            return (self.k_encoding,)
        return ("encoded",) if kdf.is_encoded(candidate) else ("mpint", "string")

    def _verify(self, candidate, ctx):
        kdf = _primitive()
        if kdf is None:
            return self._verdict("error", "primitive ssh_kdf is not available")
        if not isinstance(candidate, (bytes, bytearray, memoryview)) or not bytes(candidate):
            return self._verdict("error", "candidate must be non-empty bytes")
        exchange_hash = ctx.get("exchange_hash")
        if not isinstance(exchange_hash, (bytes, bytearray)) or not exchange_hash:
            return self._verdict("error", "ctx['exchange_hash'] (H) is required")
        session_id = ctx.get("session_id") or exchange_hash
        found = [bytes(f) for f in ctx.get("found") or () if f]
        if not found:
            return self._verdict("error", "ctx['found'] lists no keys found in memory")
        hash_name = self.hash_name or kdf.guess_hash(exchange_hash)
        if hash_name is None:
            return self._verdict("error", "cannot tell the kex hash from a %d-byte H"
                                 % len(exchange_hash))
        best = {}
        for encoding in self._encodings(kdf, bytes(candidate)):
            k_encoded = kdf.encode_shared_secret(bytes(candidate), encoding)
            derived = kdf.derive_all(k_encoded, exchange_hash, session_id, kdf.MAX_DERIVED,
                                     hash_name)
            letters = kdf.matched_letters(derived, found, self.min_match)
            if len(letters) > len(best.get("letters", {})):
                best = {"letters": letters, "encoding": encoding}
        return self._judge(kdf, best, hash_name, bool(ctx.get("trusted")))

    def _judge(self, kdf, best, hash_name, trusted):
        letters = best.get("letters", {})
        evidence = {"hash": hash_name, "k_encoding": best.get("encoding"),
                    "letters": "".join(sorted(letters)),
                    "matches": {k: {"offset": v[0], "length": v[1], "word_swapped": v[2]}
                                for k, v in sorted(letters.items())}}
        status = kdf.proof_status(len(letters), trusted)
        if status == "proven":
            return self._verdict("proven", "RFC 4253 keys %s re-derived from (K, H, session_id) "
                                 "and found in the same memory" % evidence["letters"], evidence)
        if status == "rejected":
            return self._verdict("rejected", "no RFC 4253 key derived from this K matches the "
                                 "session's own keys", evidence)
        if letters:
            return self._verdict("error", "inconclusive: only key %s matched (a proof needs %d)"
                                 % (evidence["letters"], kdf.MIN_PROVEN_LETTERS), evidence)
        return self._verdict("error", "inconclusive: no derived key is among the found keys",
                             evidence)

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
