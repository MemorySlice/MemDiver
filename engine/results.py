"""Result dataclasses for the analysis engine."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import deprecated_kwarg

logger = logging.getLogger("memdiver.engine.results")


@dataclass
class SecretHit:
    """A single secret found at a specific offset in a dump."""
    secret_type: str
    offset: int
    length: int
    dump_path: Path
    library: str
    phase: str
    run_id: int
    confidence: float = 1.0
    verified: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticRegion:
    """A contiguous region of static bytes across multiple dumps."""
    start: int
    end: int
    mean_variance: float = 0.0
    classification: str = "invariant"

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class LibraryReport:
    """Analysis results for a single library."""
    library: str
    protocol_version: str
    phase: str
    num_runs: int
    hits: List[SecretHit] = field(default_factory=list)
    static_regions: List[StaticRegion] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def tls_version(self) -> str:
        """Backward-compatible alias for protocol_version."""
        return self.protocol_version

    @tls_version.setter
    def tls_version(self, value: str) -> None:
        self.protocol_version = value


deprecated_kwarg(LibraryReport, "tls_version", "protocol_version")


@dataclass
class AnalysisResult:
    """Complete analysis result across one or more libraries."""
    libraries: List[LibraryReport] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_library(self, name: str) -> Optional[LibraryReport]:
        for lib in self.libraries:
            if lib.library == name:
                return lib
        return None

    @property
    def total_hits(self) -> int:
        return sum(len(lib.hits) for lib in self.libraries)
