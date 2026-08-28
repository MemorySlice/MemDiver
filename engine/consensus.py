"""ConsensusVector - per-byte variance analysis across multiple dumps.

Core of the 'Elimination via Variance' approach: bytes that are identical
across all runs are structural; bytes with high variance are key candidates.

The output is a 1D variance vector (one float per byte offset), computed via
Welford's online recurrence or a chunked two-pass estimator — the implicit
N×d observation matrix is never materialized.
"""

import bisect
import logging
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple, Union

import numpy as np

from memdiver.core.region_align import (
    ALIGNMENT_FILE_OFFSET,
    ALIGNMENT_METHODS,
    ALIGNMENT_MODULE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
    AlignmentCoverage,
)
from memdiver.core.variance import (
    ByteClass,
    ByteClassSpec,
    INVARIANT_MAX,
    STRUCTURAL_MAX,
    POINTER_MAX,
    VarianceThresholds,
    class_mask,
    compute_variance,
    classify_variance,
    find_contiguous_runs,
    normalize_byte_classes,
    count_classifications,
    WelfordVariance,
)
from .consensus_va import supports_va_alignment
from .results import StaticRegion

logger = logging.getLogger("memdiver.engine.consensus")

# Re-export thresholds for backward compatibility
__all__ = [
    "ConsensusVector",
    "ConsensusMatrix",  # backward-compat alias
    "INVARIANT_MAX",
    "STRUCTURAL_MAX",
    "POINTER_MAX",
    "VarianceThresholds",
    "ByteClass",
    "AlignmentReport",
    "ALIGNMENT_METHODS",
    "ALIGNMENT_MODULE_OFFSET",
    "ALIGNMENT_VIRTUAL_ADDRESS",
    "ALIGNMENT_FILE_OFFSET",
    "_is_native_msl",
]

# ---------------------------------------------------------------------------
# Alignment provenance
# ---------------------------------------------------------------------------
#
# HOW the N byte streams were put into correspondence before they were
# compared. A closed vocabulary, because a variance figure produced by
# ASLR-aware module+offset alignment and one produced by the flat-offset
# fallback are not comparable, and a reader who cannot tell them apart will
# compare them anyway.

# The alignment vocabulary lives in ``core.region_align`` -- the lowest layer
# that owns the alignment arithmetic -- so the consensus engine and the
# ``consensus_runs.alignment_method`` column validate against one tuple.
# Re-exported here because this is where callers of ``AlignmentReport``
# already look.

#: An aligned build that drops more than this share of the input bytes gets a
#: warning. Some loss is normal — a region present in one dump and not another
#: cannot be compared — but past this point the variance describes a corner of
#: the dumps rather than the dumps.
SIGNIFICANT_DISCARD_FRACTION = 0.10


@dataclass(frozen=True)
class AlignmentReport:
    """How a consensus vector's N dumps were aligned, and what that cost.

    Every consensus carries one, so no surface has to guess which path ran.
    ``bytes_compared`` is the length of the byte stream every dump contributed
    to; ``bytes_discarded`` is the total input bytes that never took part,
    summed over all dumps, so that::

        sum(input sizes) == bytes_compared * n_sources + bytes_discarded

    ``warnings`` is non-empty exactly when the result is questionable: the
    flat fallback ran on dumps of different sizes, or an aligned path kept too
    little to be representative. Equal-sized dumps on the flat path — the
    normal case for a phase-series capture of one process — stay silent.
    """

    method: str = ALIGNMENT_FILE_OFFSET
    bytes_compared: int = 0
    bytes_discarded: int = 0
    sizes_differed: bool = False
    n_sources: int = 0
    warnings: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready form for the CLI / API / MCP surfaces."""
        return {
            "method": self.method,
            "bytes_compared": self.bytes_compared,
            "bytes_discarded": self.bytes_discarded,
            "sizes_differed": self.sizes_differed,
            "n_sources": self.n_sources,
            "warnings": list(self.warnings),
        }


def _alignment_warnings(method: str, coverage: AlignmentCoverage) -> Tuple[str, ...]:
    """The warnings a given alignment outcome earns — usually none.

    The flat fallback is only reported when the dumps were not the same size,
    because that is the case where comparing byte 0 to byte 0 is unsound.
    Running the fallback on equal-sized dumps is the normal, correct case and
    a warning there would be noise on every real run.
    """
    if not coverage.n_sources:
        return ()
    if coverage.bytes_compared == 0 and sum(coverage.bytes_available):
        return (
            f"{method} alignment found no bytes common to all "
            f"{coverage.n_sources} dumps; nothing was compared.",
        )
    if method == ALIGNMENT_FILE_OFFSET:
        if not coverage.sizes_differed:
            return ()
        return (
            f"Flat file-offset alignment on {coverage.n_sources} dumps of "
            f"differing size ({min(coverage.bytes_available)}-"
            f"{max(coverage.bytes_available)} bytes): only the first "
            f"{coverage.bytes_compared} bytes of each were compared and "
            f"{coverage.bytes_discarded} bytes were discarded. Offsets were "
            f"compared without ASLR correction, so a shifted layout would "
            f"make this variance meaningless.",
        )
    if coverage.discarded_fraction > SIGNIFICANT_DISCARD_FRACTION:
        return (
            f"{method} alignment compared {coverage.bytes_compared} bytes per "
            f"dump; {coverage.bytes_discarded} bytes "
            f"({coverage.discarded_fraction:.1%} of the input) were present in "
            f"some dumps but not all and were not compared.",
        )
    return ()


def _build_report(method: str, coverage: AlignmentCoverage) -> AlignmentReport:
    """Assemble (and log) the report for one alignment outcome."""
    warnings = _alignment_warnings(method, coverage)
    for message in warnings:
        logger.warning("%s", message)
    return AlignmentReport(
        method=method,
        bytes_compared=coverage.bytes_compared,
        bytes_discarded=coverage.bytes_discarded,
        sizes_differed=coverage.sizes_differed,
        n_sources=coverage.n_sources,
        warnings=warnings,
    )


def _flat_report(sizes: Sequence[int], bytes_compared: int) -> AlignmentReport:
    """Report for a flat-offset build, from the N input sizes."""
    return _build_report(
        ALIGNMENT_FILE_OFFSET,
        AlignmentCoverage.from_sizes(sizes, bytes_compared),
    )

# String-to-ByteClass mapping for backward-compat setter
_STR_TO_BYTECLASS = {
    "invariant": ByteClass.INVARIANT,
    "structural": ByteClass.STRUCTURAL,
    "pointer": ByteClass.POINTER,
    "key_candidate": ByteClass.KEY_CANDIDATE,
}


class ConsensusVector:
    """Per-byte variance vector across N dumps at the same phase."""

    def __init__(self, thresholds: Union[VarianceThresholds, None] = None):
        # Band boundaries used by every classify pass on this vector. None
        # means the module defaults (0.0 / 200.0 / 3000.0).
        self.thresholds: Union[VarianceThresholds, None] = thresholds
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
        # Aligned builds only: per-slice VA layout
        # [(slab_offset, page_size, [va_per_dump])] in slab order, plus the
        # source dump paths in build order. Together they map any dump's
        # virtual address to the slab index that `variance` /
        # `classifications` are indexed by — so the consensus overlay can be
        # painted on a dump's `va` view. None/empty for raw (flat-offset)
        # builds, which have no VA coordinate to map to. Named for the MSL
        # path that first produced it; the VA path fills it with the same
        # slab/VA correspondence.
        self.msl_layout: Union[List[Tuple[int, int, List[int]]], None] = None
        self.dump_paths: List[str] = []
        self._va_index_cache: Dict[int, List[Tuple[int, int, int]]] = {}
        # How this vector's dumps were put into correspondence. Populated by
        # every build path; the default describes an unbuilt vector.
        self.alignment_report: AlignmentReport = AlignmentReport()
        # Input sizes seen by an incremental build, so `finalize` can report
        # the same coverage a one-shot build would have.
        self._incremental_sizes: List[int] = []

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
        sizes = [p.stat().st_size for p in dump_paths]
        min_size = min(sizes)
        if min_size == 0:
            logger.warning("Empty dump files detected")
            return

        self.size = min_size
        buffers = [p.read_bytes()[:min_size] for p in dump_paths]
        self.variance = compute_variance(buffers, min_size)
        self._classifications = classify_variance(self.variance, self.thresholds)
        self.reference_bytes = buffers[0] if buffers else b""
        self.alignment_report = _flat_report(sizes, min_size)
        logger.info("Consensus built: %d bytes, %d dumps", min_size, self.num_dumps)

    def build_from_sources(
        self, sources: List, normalize: bool = False,
    ) -> None:
        """Build consensus from DumpSource objects.

        Picks the strongest correspondence the sources can supply, and records
        which one that was in :attr:`alignment_report`:

        * every source a native ``.msl`` -> ASLR-invariant module+offset;
        * every source carrying a VA map (gcore, regioned raw) -> virtual
          address;
        * anything else — raw, mixed, imported ``.msl`` — -> the flat-offset
          fallback, unchanged.

        An aligned path that finds nothing in common yields an empty consensus
        and says so in the report; it does not silently retry flat, because
        "these dumps share no mapped page" and "these dumps agree byte for
        byte from offset 0" are different answers.
        """
        if len(sources) < 2:
            logger.warning("Need >= 2 dumps for consensus, got %d", len(sources))
            return
        self.num_dumps = len(sources)
        # Record the source order + reset any prior VA index so the overlay can
        # map a viewed dump's path -> index -> VA layout for this build.
        self.dump_paths = [str(getattr(s, "path", "") or "") for s in sources]
        self._va_index_cache = {}
        if all(_is_native_msl(s) for s in sources):
            from .consensus_msl import build_msl_consensus_result
            result = build_msl_consensus_result(sources)
            self._adopt_aligned(result, ALIGNMENT_MODULE_OFFSET)
        elif all(supports_va_alignment(s) for s in sources):
            from .consensus_va import build_va_consensus
            result = build_va_consensus(sources)
            self._adopt_aligned(result, ALIGNMENT_VIRTUAL_ADDRESS)
        else:
            self.msl_layout = None
            self._build_raw(sources)
        self._classifications = classify_variance(self.variance, self.thresholds)

    def _adopt_aligned(self, result, method: str) -> None:
        """Take an aligned build's slab, layout and coverage.

        The MSL and VA results share a shape on purpose, so both aligned paths
        land here and cannot drift in what they publish.
        """
        self.variance = result.variance
        self.size = result.total_bytes
        self.reference_bytes = result.reference_bytes
        self.msl_layout = result.layout
        self.alignment_report = _build_report(method, result.coverage)

    def _build_raw(self, sources: List) -> None:
        """Flat-bytes consensus from DumpSource objects (fallback)."""
        buffers = [s.read_all() for s in sources]
        sizes = [len(b) for b in buffers]
        min_size = min(sizes)
        if min_size == 0:
            logger.warning("Empty dump data detected")
            return
        self.size = min_size
        truncated = [b[:min_size] for b in buffers]
        self.variance = compute_variance(truncated, min_size)
        self.reference_bytes = truncated[0]
        self.alignment_report = _flat_report(sizes, min_size)

    # ------------------------------------------------------------------
    # VA-coordinate access (MSL overlay + variance heatmap)
    # ------------------------------------------------------------------

    def dump_index_for_path(self, dump_path: str) -> int:
        """Index of ``dump_path`` within this build's source order, or -1."""
        target = Path(dump_path)
        for i, p in enumerate(self.dump_paths):
            if p == str(target) or Path(p) == target:
                return i
        return -1

    def _va_index_for(self, dump_index: int) -> List[Tuple[int, int, int]]:
        """Sorted ``[(va_start, slab_offset, page_size)]`` for one dump (cached).

        Sorted by ``va_start`` so a viewed dump's virtual address can be
        binary-searched to the slab index the classification array uses.
        """
        if not self.msl_layout:
            return []
        cached = self._va_index_cache.get(dump_index)
        if cached is not None:
            return cached
        idx = [
            (int(vaddrs[dump_index]), int(slab), int(ps))
            for (slab, ps, vaddrs) in self.msl_layout
            if 0 <= dump_index < len(vaddrs)
        ]
        idx.sort(key=lambda e: e[0])
        self._va_index_cache[dump_index] = idx
        return idx

    def class_window_va(self, dump_index: int, va: int, length: int) -> List[int]:
        """Per-byte ByteClass codes for ``[va, va+length)`` in a dump's VA space.

        Entries are ByteClass codes for aligned/captured bytes and ``-1`` for VA
        gaps not present in the consensus (unmapped / not-captured-in-all-dumps).
        """
        idx = self._va_index_for(dump_index)
        length = max(0, int(length))
        out = np.full(length, -1, dtype=np.int16)
        if not idx or length == 0:
            return out.tolist()
        starts = [e[0] for e in idx]
        cls = np.asarray(self._classifications)
        # First slice that could overlap [va, va+length).
        i = max(0, bisect.bisect_right(starts, va) - 1)
        while i < len(idx) and idx[i][0] < va + length:
            va_start, slab, ps = idx[i]
            seg_start = max(va, va_start)
            seg_end = min(va + length, va_start + ps)
            if seg_end > seg_start:
                s0 = slab + (seg_start - va_start)
                s1 = slab + (seg_end - va_start)
                out[seg_start - va:seg_end - va] = cls[s0:s1].astype(np.int16)
            i += 1
        return out.tolist()

    def va_overview(self, dump_index: int, bins: int = 256) -> Dict[str, Any]:
        """Down-sampled change/variance heatmap across a dump's aligned VA span.

        Returns per-bin fractions ``changing`` (class > INVARIANT) and ``high``
        (class == KEY_CANDIDATE) plus the max ``level`` (0..3), for a whole-dump
        "what stays vs what changes" minimap. A page maps to the bin of its
        start VA (page << bin width), which is exact enough for the strip.
        """
        idx = self._va_index_for(dump_index)
        bins = max(1, int(bins))
        empty = {"va_start": 0, "va_end": 0, "bin_size": 0,
                 "changing": [], "high": [], "level": []}
        if not idx:
            return empty
        va_start = idx[0][0]
        va_end = idx[-1][0] + idx[-1][2]
        span = max(1, va_end - va_start)
        bin_size = max(1, -(-span // bins))  # ceil division
        nb = max(1, -(-span // bin_size))
        total = np.zeros(nb, dtype=np.int64)
        changing = np.zeros(nb, dtype=np.int64)
        high = np.zeros(nb, dtype=np.int64)
        level = np.zeros(nb, dtype=np.int16)
        cls = np.asarray(self._classifications)
        key_code = int(ByteClass.KEY_CANDIDATE)
        for (va0, slab, ps) in idx:
            b = (va0 - va_start) // bin_size
            if b < 0 or b >= nb:
                continue
            page_cls = cls[slab:slab + ps].astype(np.int16)
            total[b] += ps
            changing[b] += int((page_cls > 0).sum())
            high[b] += int((page_cls >= key_code).sum())
            m = int(page_cls.max()) if ps else 0
            if m > level[b]:
                level[b] = m
        safe = total > 0
        ch_frac = np.zeros(nb, dtype=np.float64)
        hi_frac = np.zeros(nb, dtype=np.float64)
        ch_frac[safe] = changing[safe] / total[safe]
        hi_frac[safe] = high[safe] / total[safe]
        return {
            "va_start": int(va_start),
            "va_end": int(va_end),
            "bin_size": int(bin_size),
            "changing": [float(x) for x in ch_frac],
            "high": [float(x) for x in hi_frac],
            "level": [int(x) for x in level],
        }

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
        self._incremental_sizes = []
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
        # The pre-truncation length, so `finalize` can report the same
        # discarded-byte count a one-shot flat build would have reported.
        self._incremental_sizes.append(len(raw))
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
        self._classifications = classify_variance(self.variance, self.thresholds)
        # An incremental fold is the flat path, one dump at a time: every
        # source was truncated to the size fixed by `build_incremental`.
        self.alignment_report = _flat_report(self._incremental_sizes, self.size)
        self._welford = None

    def _class_runs(self, classes: Tuple[ByteClass, ...]) -> List[Tuple[int, int]]:
        """Contiguous runs of bytes belonging to any class in *classes*.

        A multi-class query runs over the UNION of the classes rather than
        per class, so a region that walks POINTER -> KEY_CANDIDATE -> POINTER
        stays one region instead of fragmenting into three short ones. Real
        secrets classify as a mix (a measured 48-byte TLS 1.2 secret is 22
        KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL), so the union is the only
        grouping that keeps them retrievable at a useful ``min_length``.
        """
        if len(classes) == 1:
            return find_contiguous_runs(self._classifications, classes[0])
        mask = class_mask(self._classifications, classes)
        return find_contiguous_runs(mask.astype(np.uint8), 1)

    def _region_mean_variance(self, start: int, end: int) -> float:
        """Mean variance over [start, end) — 0.0 when no variance is loaded.

        Reduced with numpy rather than the builtin ``sum`` the old
        ``get_volatile_regions`` used: an INVARIANT run can span the whole
        dump, and a Python-level accumulation over 11M float32s is seconds.
        """
        length = end - start
        if length <= 0:
            return 0.0
        window = self.variance[start:end]
        if len(window) == 0:
            return 0.0
        return float(np.asarray(window, dtype=np.float32).mean())

    def _region_label(self, start: int, end: int,
                      classes: Tuple[ByteClass, ...]) -> str:
        """Label a region by the most volatile class it actually contains."""
        if len(classes) == 1:
            return classes[0].name.lower()
        codes = self._classifications[start:end]
        if isinstance(codes, np.ndarray):
            present = {int(c) for c in np.unique(codes).tolist()}
        else:
            present = {int(c) for c in codes}
        highest = max((c for c in classes if int(c) in present),
                      default=max(classes))
        return ByteClass(int(highest)).name.lower()

    def get_regions(
        self, byte_class: ByteClassSpec, *,
        min_length: int = 1, max_length: int = 0,
    ) -> List[StaticRegion]:
        """Contiguous regions of one or more byte classes.

        The single retrieval path over all four classes — STRUCTURAL and
        POINTER have no dedicated getter and were previously counted but
        unreachable.

        Args:
            byte_class: A single ``ByteClass`` (or its integer code), or an
                iterable of them for a union query (see ``_class_runs``).
            min_length: Shortest region to report, in bytes.
            max_length: Longest region to report; 0 means unbounded.

        Returns:
            ``StaticRegion`` rows in offset order, each carrying the region's
            mean variance and the most volatile class it contains.
        """
        classes = normalize_byte_classes(byte_class)
        regions = []
        for start, end in self._class_runs(classes):
            length = end - start
            if length < min_length:
                continue
            if max_length and length > max_length:
                continue
            regions.append(StaticRegion(
                start=start, end=end,
                mean_variance=self._region_mean_variance(start, end),
                classification=self._region_label(start, end, classes),
            ))
        return regions

    def get_static_regions(self, min_length: int = 32) -> List[StaticRegion]:
        """Find contiguous static (invariant) byte regions."""
        return self.get_regions(ByteClass.INVARIANT, min_length=min_length)

    def get_volatile_regions(self, min_length: int = 16) -> List[StaticRegion]:
        """Find contiguous high-variance (key_candidate) regions."""
        return self.get_regions(ByteClass.KEY_CANDIDATE, min_length=min_length)

    def get_aligned_candidates(
        self, block_size: int = 32, alignment: int = 16,
        density_threshold: float = 0.75, min_length: int = 16,
    ) -> List[StaticRegion]:
        """Find alignment-filtered KEY_CANDIDATE regions.

        Like get_volatile_regions but with additional alignment filtering:
        only keeps candidate blocks that are dense and aligned.
        """
        from memdiver.core.alignment_filter import alignment_filter

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
