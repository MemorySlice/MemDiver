"""X25519 Diffie-Hellman consistency oracle: a private key and a precomputed shared secret.

The candidate is a 32-byte X25519 private key. The context carries a peer public key and a
shared secret found in the SAME structure (WireGuard keeps both per peer:
``Handshake.remoteStatic`` + ``precomputedStaticStatic`` in wireguard-go,
``noise_handshake.remote_static`` + ``precomputed_static_static`` in the kernel):

* ``proven``   -- ``X25519(candidate, remote_public) == shared``. Binds the private key AND the
  peer public key to the same handshake: the shared secret is 256 bits of a one-way function
  output sitting in memory, so it cannot match by chance.
* ``rejected`` -- the computed shared secret is a different one: the candidate is not the
  private key of this (peer, shared secret) pair.
* ``error``    -- nothing to decide on: malformed input, an all-zero candidate or shared
  secret, a non-canonical peer point (it aliases another point) or a small-order one
  (all-zero output, which a zeroed buffer would otherwise "match").

Parameters: none. The optional sample (``make_sample``) pins ``remote_public`` + ``shared``
for a generated plugin; ``ctx`` (``remote_public``, ``shared``) overrides it. The sample holds
the shared secret, i.e. exactly what verification needs and nothing more. The scalar
multiplication lives in the stdlib-only primitive ``x25519`` (bound by the loader, see
``REQUIRES_PRIMITIVES``); without it ``verify`` returns an ``error`` verdict.
"""

KIND = "x25519-dh-consistency"
CANDIDATE_LENGTHS = (32,)
# Measured per verify() of a WRONG candidate, CPython 3.11.9 arm64 (best of 3): 262 us with
# ``cryptography``, 1.25 ms on the pure-Python ladder. Budget for the pure path.
COST_US = 1300
SAMPLE_KIND = ("a peer X25519 public key + the precomputed shared secret, or none when both "
               "come from the same memory (ctx['remote_public'], ctx['shared'])")
REQUIRES_PRIMITIVES = ("x25519",)
SAMPLE_MAGIC = b"MDX25519DH1"
KEY_LEN = 32


def make_sample(remote_public=None, shared=None):
    """Pack the optional peer public key and shared secret (both or neither)."""
    if remote_public is None and shared is None:
        return SAMPLE_MAGIC
    remote_public, shared = bytes(remote_public or b""), bytes(shared or b"")
    if len(remote_public) != KEY_LEN or len(shared) != KEY_LEN:
        raise ValueError("remote_public and shared must both be 32 bytes")
    return SAMPLE_MAGIC + remote_public + shared


def parse_sample(sample):
    """``(remote_public, shared)`` or ``(None, None)``."""
    if not sample:
        return None, None
    sample = bytes(sample)
    if not sample.startswith(SAMPLE_MAGIC):
        raise ValueError("not an x25519-dh-consistency sample (bad magic)")
    body = sample[len(SAMPLE_MAGIC):]
    if not body:
        return None, None
    if len(body) != 2 * KEY_LEN:
        raise ValueError("malformed x25519-dh-consistency sample: %d bytes" % len(body))
    return body[:KEY_LEN], body[KEY_LEN:]


def build_oracle(params, sample):
    """Build a verifier from the optional sample (``params`` is accepted and unused)."""
    if params is not None and not isinstance(params, dict):
        raise ValueError("params must be a dict, not %s" % type(params).__name__)
    remote_public, shared = parse_sample(sample)
    return X25519DhOracle(remote_public, shared)


def _primitive():
    return globals().get("x25519")


class X25519DhOracle:
    """Verifies an X25519 private key against a (peer public key, shared secret) pair."""

    def __init__(self, remote_public, shared):
        self.remote_public = remote_public
        self.shared = shared
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
        remote = ctx.get("remote_public") or self.remote_public
        shared = ctx.get("shared") or self.shared
        if remote is None or shared is None:
            return self._verdict("error", "remote_public and shared are required")
        candidate, remote, shared = bytes(candidate), bytes(remote), bytes(shared)
        if any(len(v) != KEY_LEN for v in (candidate, remote, shared)):
            return self._verdict("error", "candidate, remote_public and shared must be 32 bytes")
        result = primitive.dh_consistency(candidate, remote, shared)
        evidence = {"remote_public": remote.hex()}
        if result is None:
            return self._verdict("error", "undecidable: zero key or shared secret, non-canonical "
                                 "or small-order peer point", evidence)
        if result:
            return self._verdict("proven", "X25519(candidate, remote_public) equals the shared "
                                 "secret found with it", evidence)
        return self._verdict("rejected", "X25519(candidate, remote_public) is a different shared "
                             "secret", evidence)

    def _verdict(self, status, detail, derived=None):
        return {"status": status, "kind": KIND, "detail": detail, "derived": derived or {}}
