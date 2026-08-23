"""The challenge model shared by every verification resource.

A :class:`DecryptionChallenge` is one concrete "does this key decrypt this?"
question: the ciphertext, how to build the AEAD/CBC inputs, how to derive the
real cipher key from a raw candidate secret, and how to judge success. Keeping
all three of those pluggable is what lets one :class:`~memdiver.engine.resources.oracle.ResourceOracle`
serve TLS-pcap records today and, unchanged, an encrypted-file resource later:
  * ``success`` chooses tag-validity (AEAD), plaintext equality, or a custom
    validator predicate (the seam an encrypted-file resource uses — e.g. a magic
    -byte / header check).
  * ``derivation`` is optional: when ``None`` the candidate IS the key (the raw
    encrypted-file case); when set it describes the protocol KDF context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Union


class SuccessStrategy(Enum):
    """How a decryption attempt is judged successful."""

    AEAD_TAG = "aead_tag"                    # decrypt not raising == confirmed
    EXPECTED_PLAINTEXT = "expected_plaintext"  # recovered plaintext must equal a known value
    VALIDATOR = "validator"                  # a predicate over the recovered plaintext


@dataclass(frozen=True)
class DerivationContext:
    """How to turn a raw candidate secret into the concrete record cipher key.

    All fields beyond ``protocol``/``version`` are optional so a resource only
    populates what its KDF needs. ``record_iv`` carries the wire-supplied nonce
    contribution (TLS 1.2 GCM explicit nonce, or the CBC explicit IV);
    ``seq_num`` carries the record sequence number for XOR-style nonces (TLS 1.3,
    TLS 1.2 ChaCha20-Poly1305).
    """

    protocol: str                              # e.g. "TLS"
    version: str                               # e.g. "12" / "13"
    client_random: Optional[bytes] = None
    server_random: Optional[bytes] = None
    cipher_suite: Optional[Union[int, str]] = None   # IANA code (preferred) or name
    record_iv: bytes = b""                     # explicit per-record nonce/IV from the wire
    seq_num: int = 0                           # record sequence number (for XOR nonces)


@dataclass(frozen=True)
class DecryptionChallenge:
    """One decryptable unit to test a candidate key against."""

    cipher: str                                # a key in engine.verification.VERIFIER_REGISTRY
    ciphertext: bytes
    aad: bytes = b""
    tag: Optional[bytes] = None                # AEAD tag, if carried separately
    nonce: bytes = b""                         # full nonce/IV when no derivation is needed
    success: SuccessStrategy = SuccessStrategy.AEAD_TAG
    expected_plaintext: Optional[bytes] = None
    validator: Optional[Callable[[bytes], bool]] = None
    derivation: Optional[DerivationContext] = None
    label: str = ""                            # human-readable hint for logging
