"""Base class and types for KDF (Key Derivation Function) plugins.

KDF plugins are auto-discovered from core/kdf_*.py modules that contain
subclasses of BaseKDF.  This mirrors the algorithm plugin pattern in
algorithms/base.py but lives in core/ because KDF implementations are
stdlib-only cryptographic primitives.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.models import CryptoSecret


@dataclass(frozen=True)
class KDFParams:
    """Parameters for a key derivation operation."""

    hash_algo: str = "sha256"
    key_lengths: tuple = (16, 32)
    labels: tuple = ()
    context: bytes = b""
    extra: Dict[str, Any] = field(default_factory=dict)


class BaseKDF(ABC):
    """Abstract base for all KDF plugins.

    Subclasses must set *name*, *protocol*, and *versions* as class
    attributes and implement the four abstract methods.
    """

    name: str = ""
    protocol: str = ""
    versions: Set[str] = set()

    @abstractmethod
    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive output key material from *secret* using *params*."""

    @abstractmethod
    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """Expand a traffic/session secret into derived keys and IVs."""

    @abstractmethod
    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
    ) -> float:
        """Test whether *candidate_a* and *candidate_b* are KDF-related.

        Returns a confidence score between 0.0 (unrelated) and 1.0
        (confirmed relationship).
        """

    def supported_secret_types(self) -> Set[str]:
        """Return secret types this KDF can expand.

        Override in subclasses; the default returns an empty set
        (no expansion capability).
        """
        return set()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, protocol={self.protocol!r})"
