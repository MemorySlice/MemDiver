"""Result dataclasses for the analysis engine."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.core.models import deprecated_kwarg

logger = logging.getLogger("memdiver.engine.results")


@dataclass
class SecretHit:
    """A single secret found at a specific offset in a dump.

    ``run_id`` is the CORPUS RUN NUMBER (``openssl_run_13_4`` -> ``4``), not a
    foreign key into ``analysis_runs``; ``project_db.findings.run_number`` is
    where it lands.
    """
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
    # -- appended, all defaulted: no existing constructor call changes shape --
    #
    # The secret bytes as hex. ``findings.value_hex`` / ``ground_truth.value_hex``
    # have always had a column for it, but no hit type carried it, so
    # `serialize_hit` had nothing to emit and every persisted row stored NULL.
    # ``None`` (not ``""``) keeps "the producer recorded no bytes" distinct from
    # "the bytes are the empty string" all the way into the nullable column.
    value_hex: Optional[str] = None
    # The canonical (normalized) phase of the dump this hit came from, when the
    # producer knew it. Empty means "not normalized", matching the column
    # default -- never "normalized to nothing".
    canonical_phase: str = ""


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
    # -- the corpus axes, appended and defaulted -----------------------------
    #
    # BOTH persistence paths read exactly these five. The live one,
    # `engine.pipeline.AnalysisPipeline._persist_report`, reads them off this
    # object directly; `ProjectDB.persist_report` reads them off the dict
    # `serialize_report` builds from it. Until the report carried the fields —
    # and until `analyze_library` was taught to populate them — every one of
    # those columns fell back to its default, i.e. the axes were dropped.
    #
    # WHICH PATH IS LIVE, spelled out because comments here used to claim
    # otherwise: `ProjectDB.persist_report` has NO production caller. Its only
    # caller is `engine/batch.py`, reached only when `BatchRunner` was handed a
    # `project_db`, and neither production construction of it
    # (`app/pipeline/batch_task_runner.py`, `cli/dataset.py`) passes one. That
    # path is SUPPORTED BUT DORMANT; the writer that actually runs is
    # `AnalysisPipeline._persist_report`. Both are kept in step.
    #
    # Every default here is the SAME default the corresponding column declares
    # (see `engine.project_db._ADDED_COLUMNS`), so a report that resolves no
    # axes persists exactly what it persisted before.
    canonical_phase: str = ""
    library_version: str = "unknown"
    version_axis: str = "protocol_version"
    scenario: str = ""
    # Not in the original list for this change, but `persist_report` reads a
    # `protocol` key too (`projects.protocol`); without it here `serialize_report`
    # would have to sniff for the one axis of the five that has no field.
    protocol: str = ""

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
