"""ConsensusVector - per-byte variance analysis across multiple dumps.

Core of the 'Elimination via Variance' approach: bytes that are identical
across all runs are structural; bytes with high variance are key candidates.

The output is a 1D variance vector (one float per byte offset), computed via
Welford's online recurrence or a chunked two-pass estimator — the implicit
N×d observation matrix is never materialized.
"""

import bisect
import heapq
import logging
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple, Union

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
    "AlignedSegment",
    "WindowProjection",
    "ALIGNMENT_METHODS",
    "ALIGNMENT_MODULE_OFFSET",
    "ALIGNMENT_VIRTUAL_ADDRESS",
    "ALIGNMENT_FILE_OFFSET",
    "MAX_CONSENSUS_WINDOW",
    "flat_alignment_report",
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

#: Hard ceiling on the byte length of ONE consensus/hex window, in bytes.
#:
#: The same 16 KiB literal was written out three times — twice in
#: ``api/routers/analysis.py`` (``/consensus/range``, ``/consensus/va-range``)
#: and once in ``app/tools_inspect.py`` (``read_hex_raw_result``) — which meant
#: the cap a window request was actually held to depended on which door it came
#: through. It lives here, next to the coordinate math every windowed read is
#: expressed in, and every call site imports it.
MAX_CONSENSUS_WINDOW = 16384


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


# ---------------------------------------------------------------------------
# Window projection (slab <-> VA)
# ---------------------------------------------------------------------------
#
# The consensus indexes an aligned SLAB: a concatenation of the pages every
# dump had in common. A slab index is therefore not a position in any one
# dump's byte stream, and a viewer that jumps to it lands on real bytes at the
# wrong address -- a failure this repo has already shipped twice. These two
# records are the honest answer: they say, for one requested window, exactly
# which sub-ranges are in correspondence, where each one sits in EVERY dump,
# and which sub-ranges are in no correspondence at all.


@dataclass(frozen=True)
class AlignedSegment:
    """One maximal run of a window that the consensus put into correspondence.

    ``window_offset``/``length`` index the REQUESTED window, not any dump.
    ``vas[d]`` is the absolute virtual address, in dump ``d``, of the byte at
    ``window_offset`` -- parallel to ``ConsensusVector.dump_paths``.
    """

    window_offset: int
    length: int
    slab_offset: int
    layout_row: int
    vas: Tuple[int, ...]

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready form for the CLI / API / MCP surfaces."""
        return {
            "window_offset": self.window_offset,
            "length": self.length,
            "slab_offset": self.slab_offset,
            "layout_row": self.layout_row,
            "vas": list(self.vas),
        }


@dataclass(frozen=True)
class WindowProjection:
    """A requested window resolved into aligned segments and gaps.

    ``segments`` and ``gaps`` partition ``[0, length)``: ascending, disjoint,
    and summing to ``length``. That invariant is what lets a caller paint the
    window without doing any coordinate arithmetic of its own -- which is
    where the two shipped overlay bugs came from.

    ``anchor_index`` is the dump whose virtual address ``start`` is, or ``-1``
    when the window was anchored on the slab (then ``start`` is a slab offset).
    """

    anchor_index: int
    start: int
    length: int
    segments: Tuple[AlignedSegment, ...]
    gaps: Tuple[Tuple[int, int], ...]
    classes: Tuple[int, ...]

    def __post_init__(self) -> None:
        """Check the partition invariant every consumer is allowed to assume.

        Cheap relative to the walk that produced these, and it turns a
        coordinate slip into a loud failure here rather than a silently
        misplaced highlight three layers up. ``nosec B101`` throughout: these
        guard an internally-constructed invariant, not untrusted input.
        """
        spans = sorted(
            [(s.window_offset, s.length) for s in self.segments] + list(self.gaps),
        )
        cursor = 0
        for offset, run in spans:
            gap_msg = f"not a partition: expected a span at {cursor}, got one at {offset}"
            assert offset == cursor, f"window projection {gap_msg}"  # nosec B101
            assert run > 0, f"window projection has an empty span at {offset}"  # nosec B101
            cursor += run
        covers = f"covers {cursor} of {self.length} bytes"
        assert cursor == self.length, f"window projection {covers}"  # nosec B101
        counted = f"has {len(self.classes)} classes for {self.length} bytes"
        assert len(self.classes) == self.length, f"window projection {counted}"  # nosec B101

    @property
    def covered(self) -> int:
        """Bytes of the window that are in cross-dump correspondence."""
        return sum(s.length for s in self.segments)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready form for the CLI / API / MCP surfaces."""
        return {
            "anchor_index": self.anchor_index,
            "start": self.start,
            "length": self.length,
            "covered": self.covered,
            "segments": [s.to_dict() for s in self.segments],
            "gaps": [list(g) for g in self.gaps],
            "classes": list(self.classes),
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


def flat_alignment_report(
    sizes: Sequence[int], bytes_compared: int,
) -> AlignmentReport:
    """Report for a flat-offset build, from the N input sizes.

    Public because the aligned-window producer's NO-CONSENSUS path
    (``app.tools_consensus``) has to publish the very same coverage/warning
    report from sizes alone — it reads no bytes and builds no vector, but the
    client still has to be told that byte 0 was compared to byte 0 without
    ASLR correction. Reproducing that wording there would let the two drift.
    """
    return _build_report(
        ALIGNMENT_FILE_OFFSET,
        AlignmentCoverage.from_sizes(sizes, bytes_compared),
    )


#: Private alias kept for the three in-module build paths that already call it.
_flat_report = flat_alignment_report

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
        # Contiguous runs per queried class tuple. The classification array is
        # immutable once a build has produced it, so the runs derived from it
        # are too — and deriving them is a WHOLE-SLAB pass (a mask plus a run
        # scan, ~370 ms over 211 M bytes) that `count_regions` and
        # `iter_regions` each paid independently, making page 20 of a region
        # listing cost exactly as much as page 1. Dropped by
        # `_set_classifications`, the one door every assignment goes through.
        self._class_runs_cache: Dict[Tuple[int, ...], List[Tuple[int, int]]] = {}
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
        # Ascending va_start per _va_index_for row — the bisect key for the
        # VA->slab direction, one list per dump. Same derivation and same
        # lifetime as _va_index_cache; rebuilding it per call meant every VA
        # walk paid a pass over one row PER PAGE of the aligned build.
        self._va_starts_cache: Dict[int, List[int]] = {}
        # Ascending slab_offset per msl_layout row — the bisect key for the
        # slab->VA direction. Same lifetime as _va_index_cache: both are
        # derived from msl_layout and both are dropped when a build replaces
        # it. None means "not computed yet", which an empty layout would be
        # indistinguishable from if this were a list.
        self._slab_starts_cache: Union[List[int], None] = None
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
            self._set_classifications(value)
        elif isinstance(value, array):
            self._set_classifications(value)
        elif isinstance(value, list):
            if not value:
                self._set_classifications(np.array([], dtype=np.uint8))
            elif isinstance(value[0], str):
                self._set_classifications(np.array(
                    [_STR_TO_BYTECLASS[s] for s in value], dtype=np.uint8,
                ))
            else:
                self._set_classifications(np.array(value, dtype=np.uint8))
        else:
            self._set_classifications(np.array(list(value), dtype=np.uint8))

    def _set_classifications(self, value: Union[np.ndarray, array]) -> None:
        """Install a classification array and drop what was derived from it.

        The SINGLE assignment point, so a rebuild can never leave
        :attr:`_class_runs_cache` describing the previous array's runs.
        """
        self._classifications = value
        self._class_runs_cache = {}

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
        self._set_classifications(classify_variance(self.variance, self.thresholds))
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
        self._va_starts_cache = {}
        self._slab_starts_cache = None
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
        self._set_classifications(classify_variance(self.variance, self.thresholds))

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
        """Index of ``dump_path`` within this build's source order, or -1.

        Compared on RESOLVED paths, so ``/a/c/../b.msl``, a symlinked parent
        and a relative spelling all find the build that stored ``/a/b.msl``.
        Pure ``Path`` equality collapses ``.`` but cannot collapse ``..`` or a
        symlink without touching the filesystem, so it answered -1 for paths
        naming the very dump that was built.

        NOTE: this widens what ``/consensus/va-range`` and
        ``/consensus/va-overview`` accept — requests those endpoints used to
        reject as "not one of this consensus' dumps" now resolve to a dump
        index. That is the intent: the caller named the right file.
        """
        target = Path(dump_path)
        literal = str(target)
        for i, p in enumerate(self.dump_paths):
            if p == literal or Path(p) == target:
                return i
        # Only pay for the filesystem round-trip when the cheap comparison
        # found nothing.
        try:
            resolved = target.resolve()
        except OSError:
            return -1
        for i, p in enumerate(self.dump_paths):
            try:
                if Path(p).resolve() == resolved:
                    return i
            except OSError:
                continue
        return -1

    def _va_index_for(self, dump_index: int) -> List[Tuple[int, int, int]]:
        """Sorted ``[(va_start, slab_offset, page_size)]`` for one dump (cached).

        Sorted by ``(va_start, slab_offset)`` so a viewed dump's virtual
        address can be binary-searched to the slab index the classification
        array uses. ``slab_offset`` is in the key, not just ``va_start``,
        because two layout rows CAN resolve to the same VA in one dump —
        overlapping modules, which ``core.region_align.build_module_lookup``
        already warns about. Ordering those ties by slab offset makes the
        run of duplicates deterministic, which is what lets
        :meth:`_walk_va_window` back its cursor up onto the first of them
        instead of silently dropping every row but the last.
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
        idx.sort(key=lambda e: (e[0], e[1]))
        self._va_index_cache[dump_index] = idx
        return idx

    def _va_starts(self, dump_index: int) -> List[int]:
        """Cached ascending ``va_start`` per :meth:`_va_index_for` row.

        The bisect key for the VA walk, materialized once per dump for the
        same reason :meth:`_slab_starts` is: ``msl_layout`` has one row per
        PAGE, so rebuilding this list per call is a ~51,600-element pass to
        answer a question a bisect answers in 16 comparisons.
        """
        cached = self._va_starts_cache.get(dump_index)
        if cached is None:
            cached = [entry[0] for entry in self._va_index_for(dump_index)]
            self._va_starts_cache[dump_index] = cached
        return cached

    def _slab_starts(self) -> List[int]:
        """Cached ascending ``slab_offset`` per ``msl_layout`` row (bisect key).

        Both aligned builders append rows in slab order, so this is already
        sorted; it is materialized once because every slab-anchored lookup
        bisects it.
        """
        if not self.msl_layout:
            return []
        if self._slab_starts_cache is None:
            self._slab_starts_cache = [int(slab) for (slab, _ps, _v) in self.msl_layout]
        return self._slab_starts_cache

    def _layout_row_for_slab(self, slab_offset: int) -> int:
        """Index of the ``msl_layout`` row containing ``slab_offset``, or -1."""
        starts = self._slab_starts()
        i = bisect.bisect_right(starts, slab_offset) - 1
        if i < 0 or not self.msl_layout:
            return -1
        row_slab, page_size, _vaddrs = self.msl_layout[i]
        if slab_offset >= int(row_slab) + int(page_size):
            return -1
        return i

    # -- the three walks -----------------------------------------------
    #
    # Every coordinate answer this class gives comes out of one of these three
    # generators, so a fix to a walk is a fix to every consumer at once.
    #
    # The third is a COMPOSITION of the first, not a second spelling of it:
    # the VAS coordinate is piecewise-linear in VA, so a VAS window is a
    # sequence of VA-linear sub-walks re-based onto the window. Nothing about
    # VA -> slab resolution is respelled, which is what stops the VA answer and
    # the VAS answer drifting apart for the bytes they both describe.

    def _walk_va_window(
        self, dump_index: int, va: int, length: int,
    ) -> Iterator[Tuple[int, int, int, int]]:
        """Yield ``(window_offset, run_length, slab_offset, layout_row)`` per aligned run.

        THE single VA->slab walk. :meth:`class_window_va` and
        :meth:`project_va_window` both consume it, so a fix to one is a fix to
        both. Yields nothing for a raw build (``msl_layout is None``) or a
        window wholly outside the aligned span.
        """
        idx = self._va_index_for(dump_index)
        length = max(0, int(length))
        if not idx or length == 0:
            return
        va = int(va)
        end = va + length
        starts = self._va_starts(dump_index)
        # First entry that could overlap [va, end).
        i = max(0, bisect.bisect_right(starts, va) - 1)
        # bisect lands past the LAST entry sharing a va_start; back up onto the
        # first of them or overlapping rows before it would never be visited.
        while i > 0 and starts[i - 1] == starts[i]:
            i -= 1
        while i < len(idx) and idx[i][0] < end:
            va_start, slab, page_size = idx[i]
            seg_start = max(va, va_start)
            seg_end = min(end, va_start + page_size)
            if seg_end > seg_start:
                run_slab = slab + (seg_start - va_start)
                yield (
                    seg_start - va,
                    seg_end - seg_start,
                    run_slab,
                    self._layout_row_for_slab(run_slab),
                )
            i += 1

    def _walk_vas_window(
        self,
        dump_index: int,
        vas_runs: Sequence[Tuple[int, int, int]],
        vas_offset: int,
        length: int,
    ) -> Iterator[Tuple[int, int, int, int]]:
        """Same tuples for a window walked in a dump's DENSE VAS stream.

        The ``"vas"`` view is the dump's captured bytes laid end to end, so
        ``vas`` offset ``k+1`` is the byte after ``k`` even when the two sit in
        regions megabytes apart in VA. Walking such a window VA-linearly
        (:meth:`_walk_va_window`) therefore marches off the end of the first
        captured run into unmapped VA — reporting bytes every dump captured as
        a GAP — or, worse, into the next region's bytes at the wrong address.

        This is a COMPOSITION of :meth:`_walk_va_window`, not a second
        VA -> slab resolution: VAS is piecewise-linear in VA, so each captured
        run overlapping the window is one VA-linear sub-walk whose window
        offsets are re-based by where that run starts in the window.

        ``vas_runs`` is ``[(va_start, run_length, vas_offset)]`` — only the
        OPEN source knows its own region table, so it is a parameter rather
        than something this vector could derive. The contract is ASCENDING
        ``vas_offset``; the defensive sort is KEPT (a caller that yields them
        in another order still gets the right answer) but is now skipped when
        the table already satisfies the contract, which every in-tree caller
        does. Skipping it matters because the sort is O(R log R) per window and
        ``R`` is the whole PT_LOAD table for a gcore.

        Both ends of the scan are bounded: the far end by the ascending break,
        the near end by bisecting to the first run that can overlap instead of
        walking up to it from run 0.
        """
        length = max(0, int(length))
        if length == 0 or not vas_runs:
            return
        vas_offset = int(vas_offset)
        end = vas_offset + length
        starts = [int(run[2]) for run in vas_runs]
        ordered: Sequence[Tuple[int, int, int]] = vas_runs
        if any(b < a for a, b in zip(starts, starts[1:])):
            ordered = sorted(vas_runs, key=lambda r: r[2])
            starts = [int(run[2]) for run in ordered]
        first = max(0, bisect.bisect_right(starts, vas_offset) - 1)
        # Back up onto the first run sharing that offset; a zero-length run
        # parked at a real run's offset must not hide the real one.
        while first > 0 and starts[first - 1] == starts[first]:
            first -= 1
        for run_va, run_length, run_vas in ordered[first:]:
            run_length = int(run_length)
            run_vas = int(run_vas)
            if run_length <= 0:
                continue
            if run_vas >= end:
                break  # sorted ascending — nothing further overlaps
            if run_vas + run_length <= vas_offset:
                continue
            piece_start = max(vas_offset, run_vas)
            piece_end = min(end, run_vas + run_length)
            piece_va = int(run_va) + (piece_start - run_vas)
            base = piece_start - vas_offset
            for window_offset, run, slab, row in self._walk_va_window(
                dump_index, piece_va, piece_end - piece_start,
            ):
                yield (window_offset + base, run, slab, row)

    def _walk_slab_window(
        self, slab_offset: int, length: int,
    ) -> Iterator[Tuple[int, int, int, int]]:
        """Same tuples for a slab-anchored window.

        The slab is dense — the aligned builders lay rows end to end — so
        within the slab this yields one run per layout row touched and NEVER
        a gap. Only the part of a window that runs off the end of the slab is
        uncovered.
        """
        if not self.msl_layout:
            return
        length = max(0, int(length))
        slab_offset = int(slab_offset)
        if length == 0:
            return
        end = slab_offset + length
        starts = self._slab_starts()
        i = max(0, bisect.bisect_right(starts, slab_offset) - 1)
        while i < len(self.msl_layout) and starts[i] < end:
            row_slab, page_size, _vaddrs = self.msl_layout[i]
            row_slab = int(row_slab)
            seg_start = max(slab_offset, row_slab)
            seg_end = min(end, row_slab + int(page_size))
            if seg_end > seg_start:
                yield (seg_start - slab_offset, seg_end - seg_start, seg_start, i)
            i += 1

    # -- the inverse ---------------------------------------------------

    def slab_to_va(self, dump_index: int, slab_offset: int) -> int:
        """Absolute VA in ``dump_index`` of slab byte ``slab_offset``, or -1.

        THE INVERSE of what :meth:`_va_index_for` / :meth:`class_window_va`
        do. Returns -1 — never a plausible-looking address — for a raw build,
        an out-of-range ``dump_index``, or a ``slab_offset`` past the end of
        the aligned slab. A wrong-but-plausible address is worse than no
        address here: it sends a viewer to real bytes that mean nothing.
        """
        if not self.msl_layout:
            return -1
        slab_offset = int(slab_offset)
        if slab_offset < 0:
            return -1
        row = self._layout_row_for_slab(slab_offset)
        if row < 0:
            return -1
        row_slab, _page_size, vaddrs = self.msl_layout[row]
        dump_index = int(dump_index)
        if not 0 <= dump_index < len(vaddrs):
            return -1
        return int(vaddrs[dump_index]) + (slab_offset - int(row_slab))

    # -- projections ---------------------------------------------------

    def _project(
        self,
        anchor_index: int,
        start: int,
        length: int,
        runs: Iterator[Tuple[int, int, int, int]],
    ) -> "WindowProjection":
        """Turn one walk into a :class:`WindowProjection`.

        Shared by both ``project_*`` entry points so the partition invariant
        is established in exactly one place.

        Ownership is recorded per byte rather than per yielded run because
        runs CAN overlap: two layout rows may resolve to the same VA in the
        anchor dump (overlapping modules). ``class_window_va`` resolves that
        by letting the later row win, and the segments have to describe the
        same final state — otherwise they would report bytes whose classes
        came from somewhere else. Deriving maximal runs from final ownership
        makes segments non-overlapping by construction.
        """
        length = max(0, int(length))
        classes = np.full(length, -1, dtype=np.int16)
        owner_slab = np.full(length, -1, dtype=np.int64)
        owner_row = np.full(length, -1, dtype=np.int32)
        cls = np.asarray(self._classifications)
        for window_offset, run, slab, row in runs:
            stop = window_offset + run
            classes[window_offset:stop] = cls[slab:slab + run].astype(np.int16)
            owner_slab[window_offset:stop] = np.arange(slab, slab + run)
            owner_row[window_offset:stop] = row

        # A span breaks where the owning row changes, or where a covered run
        # stops being slab-contiguous. Gap bytes carry row -1 and are left
        # alone by the slab test, so a gap stays one span.
        segments: List[AlignedSegment] = []
        gaps: List[Tuple[int, int]] = []
        if length:
            breaks = np.ones(length, dtype=bool)
            if length > 1:
                same_row = owner_row[1:] == owner_row[:-1]
                contiguous = owner_slab[1:] == owner_slab[:-1] + 1
                breaks[1:] = ~(same_row & (contiguous | (owner_row[1:] < 0)))
            bounds = np.flatnonzero(breaks).tolist() + [length]
            n_dumps = len(self.msl_layout[0][2]) if self.msl_layout else 0
            for begin, stop in zip(bounds, bounds[1:]):
                row = int(owner_row[begin])
                if row < 0:
                    gaps.append((begin, stop - begin))
                    continue
                slab = int(owner_slab[begin])
                segments.append(AlignedSegment(
                    window_offset=begin,
                    length=stop - begin,
                    slab_offset=slab,
                    layout_row=row,
                    vas=tuple(self.slab_to_va(d, slab) for d in range(n_dumps)),
                ))
        return WindowProjection(
            anchor_index=int(anchor_index),
            start=int(start),
            length=length,
            segments=tuple(segments),
            gaps=tuple(gaps),
            # tolist() already yields plain ints, in C; re-wrapping each one
            # in int() was a per-byte Python round trip over the window.
            classes=tuple(classes.tolist()),
        )

    def project_va_window(
        self, anchor_index: int, va: int, length: int,
    ) -> "WindowProjection":
        """Resolve ``[va, va+length)`` in dump ``anchor_index`` to segments+gaps.

        The full answer behind :meth:`class_window_va`: same classes, plus
        where each covered run lives in the slab and in every OTHER dump.
        """
        return self._project(
            anchor_index, va, length,
            self._walk_va_window(anchor_index, va, length),
        )

    def project_vas_window(
        self,
        anchor_index: int,
        vas_runs: Sequence[Tuple[int, int, int]],
        vas_offset: int,
        length: int,
    ) -> "WindowProjection":
        """Resolve ``[vas_offset, +length)`` in a dump's DENSE VAS stream.

        The VAS sibling of :meth:`project_va_window`: same segments, gaps and
        classes, but the window is walked run-to-run through the dump's
        captured bytes instead of VA-linearly, so a window that crosses a
        captured-run boundary stays contiguous. See :meth:`_walk_vas_window`
        for why VA-linear is wrong here and for the ``vas_runs`` contract.

        :attr:`WindowProjection.start` is a VAS OFFSET here, not a virtual
        address — the coordinate the window was requested in, as for every
        other ``project_*``.

        Reusing :meth:`_project` unchanged is load-bearing: it buys the
        segments/gaps partition of ``[0, length)``, non-overlapping segments,
        and segments never wider than one layout row — which is what keeps a
        peer read inside a page every dump captured.

        (A ``class_window_vas`` would compose the same way, from the same
        walk, if a caller ever needs just the classes. None does today.)
        """
        return self._project(
            anchor_index, vas_offset, length,
            self._walk_vas_window(anchor_index, vas_runs, vas_offset, length),
        )

    def project_slab_window(
        self, slab_offset: int, length: int,
    ) -> "WindowProjection":
        """Resolve ``[slab_offset, +length)`` into segments+gaps, per dump.

        Anchored on the slab, so :attr:`WindowProjection.anchor_index` is -1
        and :attr:`WindowProjection.start` is the slab offset.
        """
        return self._project(
            -1, slab_offset, length,
            self._walk_slab_window(slab_offset, length),
        )

    def class_window_va(self, dump_index: int, va: int, length: int) -> List[int]:
        """Per-byte ByteClass codes for ``[va, va+length)`` in a dump's VA space.

        Entries are ByteClass codes for aligned/captured bytes and ``-1`` for VA
        gaps not present in the consensus (unmapped / not-captured-in-all-dumps).
        """
        out = np.full(max(0, int(length)), -1, dtype=np.int16)
        cls = np.asarray(self._classifications)
        for w, n, slab, _row in self._walk_va_window(dump_index, va, length):
            out[w:w + n] = cls[slab:slab + n].astype(np.int16)
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
        self._set_classifications(np.array([], dtype=np.uint8))

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
        self._set_classifications(classify_variance(self.variance, self.thresholds))
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

        Memoized per class tuple against :attr:`_class_runs_cache`: the runs
        are a pure function of the (immutable) classification array, and both
        :meth:`count_regions` and :meth:`iter_regions` ask for the same tuple
        back to back — as does every subsequent page of a region listing.
        """
        key = tuple(int(c) for c in classes)
        cached = self._class_runs_cache.get(key)
        if cached is not None:
            return cached
        if len(classes) == 1:
            runs = find_contiguous_runs(self._classifications, classes[0])
        else:
            mask = class_mask(self._classifications, classes)
            runs = find_contiguous_runs(mask.astype(np.uint8), 1)
        self._class_runs_cache[key] = runs
        return runs

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

    def _kept_runs(
        self, classes: Tuple[ByteClass, ...], min_length: int, max_length: int,
    ) -> Iterator[Tuple[int, int]]:
        """``(start, end)`` runs of ``classes`` surviving the length filters.

        Split out of :meth:`iter_regions` so :meth:`count_regions` can share
        the EXACT filter chain without paying for the per-region variance
        reduction — a count that disagreed with the list it is meant to size
        would turn every paginated cursor into a silent off-by-N.
        """
        for start, end in self._class_runs(classes):
            length = end - start
            if length < min_length:
                continue
            if max_length and length > max_length:
                continue
            yield (start, end)

    def iter_regions(
        self, byte_class: ByteClassSpec, *,
        min_length: int = 1, max_length: int = 0, after: int = -1,
    ) -> Iterator[StaticRegion]:
        """:meth:`get_regions`, LAZILY — the paginated retrieval path.

        Yields the same rows in the same offset order, but computes each row's
        ``mean_variance`` (and its label) only for the regions it actually
        yields. That is the difference between a bounded page and a whole-slab
        reduction: ``get_regions`` materializes EVERY region before any limit
        can apply, so a ``min_length=1`` STRUCTURAL query over an 11 MB slab
        costs ~10^5–10^6 numpy ``.mean()`` calls even when the caller wants
        200 rows.

        ``after`` is an exclusive cursor in SLAB coordinates: runs starting at
        or before it are skipped, so paging by "the last ``start`` I saw"
        cannot repeat or drop a row even if the filters change between pages.
        The default ``-1`` is before every valid start, i.e. no skipping.
        """
        classes = normalize_byte_classes(byte_class)
        after = int(after)
        for start, end in self._kept_runs(classes, min_length, max_length):
            if start <= after:
                continue
            yield StaticRegion(
                start=start, end=end,
                mean_variance=self._region_mean_variance(start, end),
                classification=self._region_label(start, end, classes),
            )

    def count_regions(
        self, byte_class: ByteClassSpec, *,
        min_length: int = 1, max_length: int = 0,
    ) -> int:
        """How many regions :meth:`iter_regions` would yield from the start.

        Run LENGTHS only — no variance reduction and no labelling — because a
        total is the one number a paginated caller needs on EVERY page, and
        paying a per-region ``.mean()`` for it would reintroduce exactly the
        whole-slab cost the lazy iterator exists to avoid.

        No ``after``: the total is the size of the whole result set, which is
        what a page counter ("201–400 of 8,412") is stated against.
        """
        classes = normalize_byte_classes(byte_class)
        return sum(1 for _run in self._kept_runs(classes, min_length, max_length))

    def rank_regions_by_length(
        self, byte_class: ByteClassSpec, *,
        min_length: int = 1, max_length: int = 0,
        descending: bool = True, offset: int = 0,
        limit: int = 200,
    ) -> List[StaticRegion]:
        """One page of regions ordered by LENGTH rather than by slab offset.

        The "show me the biggest key candidates first" query. An analyst
        hunting a secret of a known size does not want to walk 17,000 regions
        in address order, and a client-side sort of the rows already loaded
        would rank one page against itself and call it the top of the list —
        true only by accident.

        SORTS WITHOUT MATERIALIZING. Built on :meth:`_kept_runs`, which yields
        ``(start, end)`` with no variance reduction and no labelling, so the
        heap walks cheap tuples; only the ``offset + limit + 1`` survivors are
        turned into :class:`StaticRegion` (the ``+ 1`` is the one row past the
        page that lets a caller report ``truncated`` without counting twice).
        Ordering a whole slab through :meth:`get_regions` would reintroduce
        exactly the ~10^5-10^6 ``.mean()`` calls :meth:`iter_regions` exists
        to avoid.

        TIE-BREAK. The key is ``(length, start)``, a TOTAL order, so paging is
        deterministic and equal-length regions never reshuffle between pages.
        The two directions are not mirror images: descending negates ``start``
        so that ties still surface the LOWEST offset first, which is the
        reading order of every other list in this app.

        :param descending: Longest first when ``True``, shortest first
            otherwise.
        :param offset: How many ranked rows to skip — a RANK cursor, not a
            slab offset. Sorted pagination cannot use the slab-offset cursor
            :meth:`iter_regions` takes, because rank order and slab order are
            unrelated.
        :param limit: Rows per page.
        """
        classes = normalize_byte_classes(byte_class)
        offset = max(0, int(offset))
        limit = max(1, int(limit))
        wanted = offset + limit + 1
        runs = self._kept_runs(classes, min_length, max_length)
        if descending:
            ranked = heapq.nlargest(
                wanted, runs, key=lambda r: (r[1] - r[0], -r[0]))
        else:
            ranked = heapq.nsmallest(
                wanted, runs, key=lambda r: (r[1] - r[0], r[0]))
        return [
            StaticRegion(
                start=start, end=end,
                mean_variance=self._region_mean_variance(start, end),
                classification=self._region_label(start, end, classes),
            )
            for start, end in ranked[offset:]
        ]

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

        Expressed as ``list(self.iter_regions(...))`` so the eager and the
        lazy path cannot drift: there is ONE filter chain and ONE row builder.
        """
        return list(self.iter_regions(
            byte_class, min_length=min_length, max_length=max_length,
        ))

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
