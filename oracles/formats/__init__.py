"""Self-contained format oracles: one module per on-disk secret format.

A format oracle proves that a candidate key recovered from memory is THE key
of some artefact, using only files or headers of that artefact (a vault
config, one encrypted file, ...). It never looks at network traffic.

Every module in this package is discovered by ``memdiver.oracles`` through its
``KIND`` and is also copied verbatim into generated single-file Volatility 3
plugins by ``memdiver.oracles.embed``. Both uses depend on the contract below,
so every new format module follows it.

The format-module contract
--------------------------

1. Module level imports are **standard library only**. No ``memdiver`` import
   and no third-party import (``cryptography`` included) at module level.
   A third-party backend (``cryptography`` or ``pycryptodome``, the only two
   allowed) is imported lazily, inside a function; when it is missing, the
   format falls back to the next backend (ultimately a pure-Python primitive)
   and only when none is usable does ``verify`` return an ``error`` verdict
   naming what is missing, instead of raising.

2. The source is **paste-safe**: no relative imports, no use of ``__file__``
   or of package paths, no ``from __future__`` imports, and no line that
   starts with the inliner's block marker (``# --- memdiver``) in column 0.
   The module must work unchanged when its text is pasted into another file
   or ``exec``-ed into a fresh module object. Keep it Python 3.8 compatible
   (no PEP 604 ``X | Y`` or ``list[int]`` annotations that are evaluated),
   because Volatility 3 still runs there.

3. Module-level names, all required unless marked optional:

   ``KIND``
       Registry key, e.g. ``"gocryptfs-gcm"``. Unique across the package.
   ``CANDIDATE_LENGTHS``
       Tuple of every candidate key length (bytes) the format can accept in
       any configuration. A built oracle also exposes ``candidate_lengths``,
       exact for its configuration (cipher, master vs derived key); plugin
       synthesizers and scanners size their candidate windows from that
       instance attribute, not from the module constant.
   ``COST_US``
       Measured microseconds per ``verify`` call, as a constant, so a
       caller can budget a candidate sweep before running it.
   ``SAMPLE_KIND``
       Short human-readable description of the evidence the oracle needs.
   ``build_oracle(params: dict, sample: bytes) -> oracle``
       Builds a verifier from caller parameters and a sample blob produced
       by ``make_sample``. Raises ``ValueError`` for a malformed sample or
       contradictory parameters (fail fast, once), never for a missing
       backend.
   ``oracle.verify(candidate: bytes, ctx: dict) -> dict``
       Never raises. Returns a plain dict verdict
       ``{"status", "kind", "detail", "derived"}`` with ``status`` one of
       ``"proven"``, ``"rejected"``, ``"error"`` and ``derived`` a dict of
       evidence (derived keys, digests). A plain dict keeps the module
       self-contained; ``memdiver.oracles.verdict_from`` normalises it.
       A malformed candidate (wrong type) or an unusable sample (truncated)
       is ``error``, never ``rejected``: "rejected" must mean "this key is
       not the key".
   ``make_sample(...) -> bytes``
       Packs the evidence into a compact, self-describing blob of at most
       8 KiB (it is embedded base64 in generated plugins). The blob must not
       carry more secret material than verification needs.
   ``REQUIRES_PRIMITIVES`` (optional)
       Tuple of names of stdlib-only crypto modules living at
       ``vol3plugins/linux/secrets/<name>.py`` (e.g. ``"aes"``). The loader
       binds each available primitive as a module global of that name AFTER
       the format module's top level has run -- in a generated plugin the
       inline loader binds the inlined copy, in the repository the registry
       (``memdiver.oracles.bind_primitives``, run by ``get_format``) binds the
       installed module -- so use primitives only inside functions, look them
       up with ``globals().get("<name>")``, and fall back (or return an
       ``error`` verdict) when the lookup yields ``None``. Never import a
       primitive (or ``memdiver``) directly. Every declared primitive must
       exist when a plugin is generated: the inliner refuses to emit a plugin
       that silently lacks one.

   Optional attributes of the BUILT oracle object (a generated plugin reads
   them with ``getattr``; leaving them out keeps the old behaviour):

   ``oracle.cost_us``
       Microseconds per ``verify`` for THIS configuration (a KDF iteration
       count read from the sample, say). Defaults to the module's
       ``COST_US``. A generated plugin multiplies the candidate count by it
       (x20 when ``oracle.backend == "pure-python"``) to log one estimate
       and to report what an exhausted ``--oracle-budget`` left undone.
   ``oracle.prefilter(candidate: bytes) -> Optional[str]``
       A rejection reason, or ``None`` to let ``verify`` decide. It runs on
       every candidate before any ``verify``, so it must be cheap (about
       20 us at most: structure, range, weak-key checks) and never a KDF.
       Return a reason only when the candidate certainly is not the key: the
       plugin reports it as ``rejected`` with Detail ``prefilter: <reason>``.
       An exception is treated as ``None``.
   ``oracle.unique``
       ``True`` when the sample admits exactly one correct key (a KDF-wrapped
       key slot, a MAC over known data). Once one candidate is proven, a
       generated plugin stops verifying and reports the rest ``unverified``
       with Detail ``skipped: key already proven``.

   ``verify`` gets a ``ctx`` dict in a generated plugin: the recipe's static
   ``oracle.ctx`` (JSON values only) merged under the run-time keys
   ``found`` (tuple of every candidate key of the pass that passed the
   filters), ``layer`` (the scanned layer name), ``read(offset, length)``
   (padded bytes of that layer), ``offset`` (the candidate's first site) and
   ``locators`` (names of the locators that found it). Ignore what you do not
   need; never raise on a missing key.

   A plugin never verifies past its ``--oracle-budget`` (default 120 s):
   candidates still waiting stay ``unverified``, never ``rejected``.

4. What "proven" means. AEADs such as AES-GCM and (X)ChaCha20-Poly1305 are
   not key-committing: a sample crafted on purpose can authenticate under
   two chosen keys. "proven" therefore means "this key authenticates the
   sample"; it identifies THE key for artefacts that the real software
   produced, which is the forensic setting. Each format documents this.
"""
