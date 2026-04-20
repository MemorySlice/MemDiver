"""ConsensusVector - per-byte variance analysis across multiple dumps.

Core of the 'Elimination via Variance' approach: bytes that are identical
across all runs are structural; bytes with high variance are key candidates.

The output is a 1D variance vector (one float per byte offset), computed via
Welford's online recurrence or a chunked two-pass estimator — the implicit
N×d observation matrix is never materialized.
"""

import logging
from array import array
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

import numpy as np

from core.variance import (
    ByteClass,
    INVARIANT_MAX,
    STRUCTURAL_MAX,
    POINTER_MAX,
    compute_variance,
    classify_variance,
    find_contiguous_runs,
    count_classifications,
    WelfordVariance,
)
from .results import StaticRegion

logger = logging.getLogger("memdiver.engine.consensus")

# Re-export thresholds for backward compatibility
__all__ = [
    "ConsensusVector",
    "ConsensusMatrix",  # backward-compat alias
    "INVARIANT_MAX",
    "STRUCTURAL_MAX",
    "POINTER_MAX",
    "ByteClass",
    "_is_native_msl",
]

# String-to-ByteClass mapping for backward-compat setter
_STR_TO_BYTECLASS = {
    "invariant": ByteClass.INVARIANT,
    "structural": ByteClass.STRUCTURAL,
    "pointer": ByteClass.POINTER,
    "key_candidate": ByteClass.KEY_CANDIDATE,
}


class ConsensusVector:
    """Per-byte variance vector across N dumps at the same phase."""

    def __init__(self):
        self.variance: Union[np.ndarray, array] = np.array([], dtype=np.float32)
        self._classifications: Union[np.ndarray, array] = np.array([], dtype=np.uint8)
        self.num_dumps: int = 0
        self.size: int = 0
        self.region_results: Dict[str, Any] = {}
        self._welford: Union[WelfordVariance, None] = None
        # Reference bytes parallel to self.variance. For build(paths) this
        # is the first dump's raw file bytes truncated to min_size. For
        # build_from_sources() it is the first source's aligned data in
        # the same slice order as the variance array. Used by downstream
        # pattern generation to derive static masks (variance == 0) and
        # reference content at the same self-consistent offsets.
        self.reference_bytes: bytes = b""

    @property
    def classifications(self) -> array:
        """Per-byte classification codes (ByteClass IntEnum values)."""
        return self._classifications

    @classifications.setter
    def classifications(self, value) -> None:
        """Accept numpy array, array('B'), List[str], or List[int].

        run.py constructs classifications from string lists, so we convert
        on assignment. numpy arrays from classify_variance are passed through.
        """
        if isinstance(value, np.ndarray):
            self._classifications = value
        elif isinstance(value, array):
            self._classifications = value
        elif isinstance(value, list):
            if not value:
                self._classifications = np.array([], dtype=np.uint8)
            elif isinstance(value[0], str):
                self._classifications = np.array(
                    [_STR_TO_BYTECLASS[s] for s in value], dtype=np.uint8,
                )
            else:
                self._classifications = np.array(value, dtype=np.uint8)
        else:
            self._classifications = np.array(list(value), dtype=np.uint8)

    def build(self, dump_paths: List[Path]) -> None:
        """Compute per-byte variance across all dump files.

        Applies a chunked two-pass estimator via ``core.variance.compute_variance``;
        numerically stable and peak-memory-bounded by ``CHUNK_BYTES`` regardless
        of dump size.
        """
        if len(dump_paths) < 2:
            logger.warning("Need at least 2 dumps for consensus, got %d", len(dump_paths))
            return

        self.num_dumps = len(dump_paths)
        min_size = min(p.stat().st_size for p in dump_paths)
        if min_size == 0:
            logger.warning("Empty dump files detected")
            return

        self.size = min_size
        buffers = [p.read_bytes()[:min_size] for p in dump_paths]
        self.variance = compute_variance(buffers, min_size)
        self._classifications = classify_variance(self.variance)
        self.reference_bytes = buffers[0] if buffers else b""
        logger.info("Consensus built: %d bytes, %d dumps", min_size, self.num_dumps)

    def build_from_sources(
        self, sources: List, normalize: bool = False,
    ) -> None:
        """Build consensus from DumpSource objects.

        Native MSL sources use ASLR-aware region alignment when *normalize* is True.
        Raw, mixed, or imported-MSL sources fall back to flat bytes.
        """
        if len(sources) < 2:
            logger.warning("Need >= 2 dumps for consensus, got %d", len(sources))
            return
        self.num_dumps = len(sources)
        if all(_is_native_msl(s) for s in sources):
            from .consensus_msl import build_msl_consensus
            (
                self.variance,
                self.size,
                self.reference_bytes,
            ) = build_msl_consensus(sources, self.num_dumps)
        else:
            self._build_raw(sources)
        self._classifications = classify_variance(self.variance)

    def _build_raw(self, sources: List) -> None:
        """Flat-bytes consensus from DumpSource objects (fallback)."""
        buffers = [s.read_all() for s in sources]
        min_size = min(len(b) for b in buffers)
        if min_size == 0:
            logger.warning("Empty dump data detected")
            return
        self.size = min_size
        truncated = [b[:min_size] for b in buffers]
        self.variance = compute_variance(truncated, min_size)
        self.reference_bytes = truncated[0]

    # ------------------------------------------------------------------
    # Incremental / live-update API (Welford-backed)
    # ------------------------------------------------------------------

    def build_incremental(self, size: int) -> None:
        """Begin an incremental consensus build of *size* bytes per dump.

        Use ``add_source`` to fold dumps in one at a time and ``finalize`` to
        materialize the variance vector and classifications.
        """
        self._welford = WelfordVariance(size)
        self.size = size
        self.num_dumps = 0
        self.reference_bytes = b""
        self.variance = np.zeros(size, dtype=np.float32)
        self._classifications = np.array([], dtype=np.uint8)

    def add_source(self, source) -> Tuple[int, float, float]:
        """Fold one dump into an incremental build. Returns live stats.

        Accepts a raw ``bytes`` buffer or any ``DumpSource``-like object
        exposing ``read_all()``. The first dump seen is cached as
        ``reference_bytes`` for downstream consumers. Returns
        ``(num_dumps, mean_variance, max_variance)``.
        """
        if self._welford is None:
            raise RuntimeError("call build_incremental() before add_source()")
        raw = source if isinstance(source, (bytes, bytearray)) else source.read_all()
        if len(raw) < self.size:
            raise ValueError(
                f"dump shorter than consensus size ({len(raw)} < {self.size})"
            )
        data = raw[: self.size]
        self._welford.add_dump(data)
        self.num_dumps = self._welford.num_dumps
        if not self.reference_bytes:
            self.reference_bytes = bytes(data)
        current = self._welford.variance()
        return self.num_dumps, float(current.mean()), float(current.max())

    def get_live_variance(self) -> np.ndarray:
        """Return the current variance vector.

        During an incremental build this reflects the Welford state at the
        moment of the call; after ``finalize()`` it returns the materialized
        vector. Public accessor so API/UI layers do not reach into the
        private Welford accumulator.
        """
        if self._welford is not None:
            return self._welford.variance()
        return self.variance

    def welford_state(self):
        """Return (mean, m2, n) — must be called BEFORE finalize()."""
        if self._welford is None:
            raise RuntimeError("unavailable after finalize()")
        return self._welford.state_arrays()

    def finalize(self) -> None:
        """Materialize ``variance`` and ``classifications`` from the Welford
        accumulator and release the incremental state."""
        if self._welford is None:
            raise RuntimeError("no incremental build in progress")
        if self.num_dumps < 2:
            logger.warning(
                "Finalizing with fewer than 2 dumps (%d); variance will be zero",
                self.num_dumps,
            )
        self.variance = self._welford.variance()
        self._classifications = classify_variance(self.variance)
        self._welford = None

    def get_static_regions(self, min_length: int = 32) -> List[StaticRegion]:
        """Find contiguous static (invariant) byte regions."""
        raw_runs = find_contiguous_runs(self._classifications, ByteClass.INVARIANT)
        regions = []
        for start, end in raw_runs:
            if (end - start) >= min_length:
                regions.append(StaticRegion(
                    start=start, end=end,
                    mean_variance=0.0, classification="invariant",
                ))
        return regions

    def get_volatile_regions(self, min_length: int = 16) -> List[StaticRegion]:
        """Find contiguous high-variance (key_candidate) regions."""
        raw_runs = find_contiguous_runs(self._classifications, ByteClass.KEY_CANDIDATE)
        regions = []
        for start, end in raw_runs:
            if (end - start) >= min_length:
                mean_var = sum(self.variance[start:end]) / (end - start)
                regions.append(StaticRegion(
                    start=start, end=end,
                    mean_variance=mean_var, classification="key_candidate",
                ))
        return regions

    def get_aligned_candidates(
        self, block_size: int = 32, alignment: int = 16,
        density_threshold: float = 0.75, min_length: int = 16,
    ) -> List[StaticRegion]:
        """Find alignment-filtered KEY_CANDIDATE regions.

        Like get_volatile_regions but with additional alignment filtering:
        only keeps candidate blocks that are dense and aligned.
        """
        from core.alignment_filter import alignment_filter

        # Extract KEY_CANDIDATE offsets (vectorized)
        candidate_offsets = set(
            np.where(self._classifications == ByteClass.KEY_CANDIDATE)[0].tolist()
        )

        if not candidate_offsets:
            return []

        # Apply alignment filter
        aligned = alignment_filter(
            candidate_offsets,
            block_size=block_size,
            alignment=alignment,
            density_threshold=density_threshold,
        )

        if not aligned:
            return []

        # Group into contiguous regions
        sorted_offsets = sorted(aligned)
        regions = []
        start = sorted_offsets[0]
        prev = start
        for offset in sorted_offsets[1:]:
            if offset != prev + 1:
                # End of contiguous region
                length = prev - start + 1
                if length >= min_length:
                    mean_var = float(sum(self.variance[start:prev + 1]) / length)
                    regions.append(StaticRegion(
                        start=start, end=prev + 1,
                        mean_variance=mean_var,
                        classification="key_candidate",
                    ))
                start = offset
            prev = offset
        # Last region
        length = prev - start + 1
        if length >= min_length:
            mean_var = float(sum(self.variance[start:prev + 1]) / length)
            regions.append(StaticRegion(
                start=start, end=prev + 1,
                mean_variance=mean_var,
                classification="key_candidate",
            ))

        return regions

    def classification_counts(self) -> Dict[str, int]:
        """Count bytes in each classification category."""
        return count_classifications(self._classifications)


# Backward-compatible alias (same pattern as TLSSecret = CryptoSecret)
ConsensusMatrix = ConsensusVector


def _is_native_msl(source) -> bool:
    """Check if a source is a native (non-imported) MSL file."""
    if getattr(source, "format_name", "") != "msl":
        return False
    reader = source.get_reader()
    return not reader.file_header.imported
