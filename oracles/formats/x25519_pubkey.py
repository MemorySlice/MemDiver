"""X25519 key-pair oracle: a candidate private key is proven by its own public key.

The candidate is a 32-byte X25519 (RFC 7748) private key, e.g. a WireGuard static private
key found in a process or kernel image. The evidence is the matching public key: either the
one the sample pins (the ``PublicKey`` of a peer's ``wg`` config, which is public) or the one
found next to the candidate in the SAME memory (``ctx["public"]``, the ``pubkey_adjacency``
layout of ``Device.staticIdentity`` / ``noise_static_identity``).

* ``proven``   -- ``X25519(candidate, 9) == public``. X25519 is a function of the clamped
  scalar, so a match identifies the key (up to the clamping bits that X25519 ignores).
* ``rejected`` -- the public key of the candidate is a different one.
* ``error``    -- no public key to compare with, malformed input (not 32 bytes, all zero).

Nothing outside memory or the public key is involved (no capture file, no traffic). The
sample carries only the public key. The scalar multiplication lives in the stdlib-only
primitive ``x25519`` (``vol3plugins/linux/secrets/x25519.py``, bound by the loader, see
``REQUIRES_PRIMITIVES``); without it ``verify`` returns an ``error`` verdict.
"""

KIND = "x25519-pubkey"
CANDIDATE_LENGTHS = (32,)
# Measured per verify() of a WRONG candidate, CPython 3.11.9 arm64 (best of 3): 262 us with
# ``cryptography``, 1.25 ms on the pure-Python ladder. Budget for the pure path.
COST_US = 1300
SAMPLE_KIND = ("the 32-byte X25519 public key (public material), or none when the public key "
               "is found next to the candidate in memory (ctx['public'])")
REQUIRES_PRIMITIVES = ("x25519",)
SAMPLE_MAGIC = b"MDX25519PUB1"
KEY_LEN = 32


def make_sample(public_key=None):
    """Pack an optional 32-byte public key (no secret material)."""
    if public_key is None:
        return SAMPLE_MAGIC
    public_key = bytes(public_key)
    if len(public_key) != KEY_LEN:
        raise ValueError("an X25519 public key is 32 bytes, got %d" % len(public_key))
    return SAMPLE_MAGIC + public_key


def parse_sample(sample):
    """The pinned public key, or ``None`` (empty sample or a sample without one)."""
    if not sample:
        return None
    sample = bytes(sample)
    if not sample.startswith(SAMPLE_MAGIC):
        raise ValueError("not an x25519-pubkey sample (bad magic)")
    body = sample[len(SAMPLE_MAGIC):]
    if body and len(body) != KEY_LEN:
        raise ValueError("malformed x25519-pubkey sample: %d-byte public key" % len(body))
    return body or None


def build_oracle(params, sample):
    """Build a verifier; ``params["public_key"]`` (bytes or hex) overrides the sample."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    public = params.get("public_key")
    if isinstance(public, str):
        public = bytes.fromhex(public)
    if public is not None and len(bytes(public)) != KEY_LEN:
        raise ValueError("public_key must be 32 bytes")
    return X25519PubkeyOracle(bytes(public) if public is not None else parse_sample(sample))


def _primitive():
    return globals().get("x25519")


class X25519PubkeyOracle:
    """Verifies an X25519 private key against its public key."""

    def __init__(self, public):
        self.public = public
        self.candidate_lengths = CANDIDATE_LENGTHS

    def verify(self, candidate, ctx=None):
        """Return a plain-dict verdict; never raises."""
        try:
            return self._verify(candidate, ctx or {})
        except Exception as exc:  # the contract: a verdict, never an exception
            return self._verdict("error", "verify failed: %r" % (exc,))

    def _verify(self, candidate, ctx):
        primitive = _primitive()
        if primitive is None:
            return self._verdict("error", "primitive x25519 is not available")
        if not isinstance(candidate, (bytes, bytearray, memoryview)):
            return self._verdict("error", "candidate must be bytes")
        candidate = bytes(candidate)
        if len(candidate) != KEY_LEN or not any(candidate):
            return self._verdict("error", "candidate must be 32 non-zero bytes")
        public = ctx.get("public") or self.public
        if not public or len(bytes(public)) != KEY_LEN or not any(bytes(public)):
            return self._verdict("error", "no 32-byte public key (sample or ctx['public'])")
        evidence = {"public": bytes(public).hex(), "clamped": primitive.is_clamped(candidate)}
        if primitive.proves_public(candidate, public):
            return self._verdict("proven", "X25519(candidate)*G equals the public key", evidence)
        return self._verdict("rejected", "the candidate's public key is a different one",
                             evidence)

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
