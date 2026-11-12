"""Self-contained secret-proving primitives for MemDiver's Linux Volatility 3 plugins.

The dm-crypt, WireGuard and fscrypt plugins use these modules to PROVE that a key recovered
from a memory image is the real one, from the image alone: an AES key schedule found next
to the raw key, a decrypted XTS sector that parses, an X25519 private key whose public key
matches the peer table, an fscrypt key identifier recomputed from the kernel's HKDF state.

What lives here
---------------
* ``aes``           -- AES block/ECB/CBC/XTS/GCM/SIV, dm-crypt ESSIV, and the exact key-schedule
  layouts the kernel keeps in ``struct crypto_aes_ctx`` (``key_enc`` / ``key_dec``).
* ``chacha``        -- ChaCha20, HChaCha20, Poly1305 and (X)ChaCha20-Poly1305, pure Python only:
  the no-library tier of the gocryptfs format oracle (XChaCha vaults).
* ``x25519``        -- RFC 7748 X25519 (WireGuard static and ephemeral keys), clamping.
* ``hkdf_midstate`` -- pure-Python SHA-512 compression and HMAC/HKDF-Expand resumed from the
  HMAC-SHA512 ipad/opad midstates that fscrypt keeps instead of its HKDF PRK, plus the
  parsers for both kernel layouts of that state and fscrypt's info-string/identifier rules.

The self-contained rule (enforced by ``tests/test_vol3plugins_secrets_aes.py``)
--------------------------------------------------------------------------------
Every file in this directory is also *source-inlined* into generated single-file plugins, so
each one must keep working when pasted alone into another ``.py`` file under stock ``vol``
with neither MemDiver nor ``cryptography`` installed:

* module level imports the Python standard library only -- never ``memdiver``,
  ``volatility3`` or a sibling module, and no relative imports;
* no ``__file__`` and no ``from __future__`` (it is a SyntaxError anywhere but the top of the
  file the module is pasted into);
* ``cryptography`` is an optional accelerator, imported lazily inside a function behind
  ``try/except``; the pure-Python path must return byte-identical results.  Setting the
  environment variable ``MEMDIVER_PUREPY_CRYPTO=1`` forces the pure path (read at call time);
  each module's ``backend()`` reports which path is active;
* private names carry a per-module prefix (``_aes_``, ``_x25519_``, ``_sha512_`` ...) so two
  modules can share one namespace; the public ``backend()`` is the only name they share, so
  inline each module into its own namespace (or rename ``backend``) when combining them.
"""
