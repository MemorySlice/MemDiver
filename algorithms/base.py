"""Base classes for analysis algorithms."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from memdiver.core.models import CryptoSecret, deprecated_kwarg


@dataclass
class AnalysisContext:
    """Context provided to algorithms."""
    library: str
    protocol_version: str
    phase: str
    secrets: List[CryptoSecret] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def tls_version(self) -> str:
        """Backward-compatible alias for protocol_version."""
        return self.protocol_version

    @tls_version.setter
    def tls_version(self, value: str) -> None:
        self.protocol_version = value


deprecated_kwarg(AnalysisContext, "tls_version", "protocol_version")


@dataclass
class Match:
    """A single match found by an algorithm."""
    offset: int
    length: int
    confidence: float
    label: str = ""
    data: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlgorithmResult:
    """Result from running an algorithm."""
    algorithm_name: str
    confidence: float
    matches: List[Match] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAlgorithm(ABC):
    """Base class for all analysis algorithms."""

    name: str = ""
    description: str = ""
    mode: str = ""  # Use KNOWN_KEY or UNKNOWN_KEY from core.constants

    @abstractmethod
    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        """Run the algorithm on dump data."""
        ...

    def estimate_working_set(
        self,
        size: int,
        context: Optional[AnalysisContext] = None,
        sample: Optional[Sequence[bytes]] = None,
    ) -> int:
        """Predicted peak heap (bytes) of :meth:`run` on a *size*-byte dump.

        Counts only what the algorithm allocates on top of ``dump_data``
        itself (the caller budgets the dump buffer). ``context`` carries the
        same ``extra`` parameters :meth:`run` will see; ``sample`` is an
        optional list of blocks read from the dump, for algorithms whose cost
        depends on content. Implementations must be conservative (an
        over-estimate, never far below the measured peak). Default ``0``:
        no size-proportional working set.
        """
        return 0
