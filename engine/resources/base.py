"""The VerificationResource protocol."""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from memdiver.engine.resources.challenge import DecryptionChallenge


@runtime_checkable
class VerificationResource(Protocol):
    """A user-supplied artifact a candidate key can be verified against.

    Implementations parse their artifact once and yield one or more
    :class:`DecryptionChallenge`s. They declare the ``protocol`` they target so a
    :class:`~memdiver.engine.resources.oracle.ResourceOracle` can route key
    derivation appropriately (TLS today; extensible via the KDF registry).
    """

    @property
    def protocol(self) -> str: ...

    def challenges(self) -> Iterable[DecryptionChallenge]: ...
