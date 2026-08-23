"""Verification resources — user-supplied artifacts a candidate key is tested against.

A :class:`VerificationResource` yields typed :class:`DecryptionChallenge`s that a
:class:`ResourceOracle` runs a candidate key through, reusing the C1 cipher
verifiers and the TLS KDF layer. The first resource is :class:`TlsPcapResource`
(prove a memory-recovered key decrypts real captured TLS traffic). The layering
is deliberately protocol- and artifact-agnostic so future resources (e.g. an
encrypted-file / ransomware resource, or non-TLS protocols) attach without
changing the oracle or the verifier protocol.
"""

from memdiver.engine.resources.challenge import (
    DecryptionChallenge,
    DerivationContext,
    SuccessStrategy,
)
from memdiver.engine.resources.base import VerificationResource
from memdiver.engine.resources.oracle import ResourceOracle

__all__ = [
    "DecryptionChallenge",
    "DerivationContext",
    "SuccessStrategy",
    "VerificationResource",
    "ResourceOracle",
]
