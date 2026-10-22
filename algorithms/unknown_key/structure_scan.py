"""Structure scanning algorithm — identify known data structures in memory.

Combines entropy analysis with structure overlay matching to find regions
that match known cryptographic or protocol-specific memory layouts.

Shape-based design (the built-in key structures only constrain ``not_zero``,
so ANY random offset "matches" them; what identifies a key is the *shape* of
the high-entropy region it sits in):

1. **Regions.** Exact step-1 high-entropy regions at window
   :data:`_SCAN_WINDOW` and the window-aware default threshold
   (:func:`~memdiver.core.entropy.default_entropy_threshold`, 4.5 at 32), via
   :func:`~memdiver.core.entropy_overview.stream_entropy_overview` with the
   Entropy tab's region rules (``region_min_span`` / ``region_join_gap``).
   The dump is streamed in :data:`_CHUNK_BYTES` views (overlapping by
   :data:`_CHUNK_OVERLAP`), never copied.
2. **Candidates.** A region is a candidate for size ``S`` only if its covered
   byte span fits ``S`` within the window-edge tolerance
   ``[S - _SPAN_BELOW, S + _SPAN_ABOVE]`` (derivation at the constants).
   Inside it, at most ``span - S + 1`` (<= 63) offsets are probed per size;
   an offset passes when its ``S`` bytes look random (collision count within
   the uniform-random bound, both edge blocks random-looking). The largest
   passing size wins, preferring 16- then 8-aligned offsets; ONE bounded
   :func:`best_match_structure` call (on just those ``S`` bytes, against the
   structures of that size) names it.
3. **Bulk.** Regions longer than any structure plus the tolerance (encrypted
   pages, compressed data) are counted in ``skipped_bulk_regions`` /
   ``skipped_bulk_bytes`` and not scanned.
4. **Magic.** Structures with an exact ``equals`` field (e.g.
   ``elf64_header``) are found by a ``find`` of the magic over the whole
   buffer, independent of entropy.
5. **Confidence** = shape fit (span vs size, randomness) x constraint score.
   At most :data:`MAX_MATCHES` matches (``truncated`` in metadata).

``dump_data`` may be any buffer (``bytes``, ``bytearray``, ``mmap``,
``memoryview``).
"""

import logging
import math
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.algorithms import working_set
from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.app.entropy_payload import region_join_gap, region_min_span
from memdiver.core.constants import UNKNOWN_KEY
from memdiver.core.entropy import default_entropy_threshold
from memdiver.core.entropy_overview import stream_entropy_overview
from memdiver.core.structure_defs import StructureDef
from memdiver.core.structure_library import StructureLibrary, get_structure_library
from memdiver.core.structure_overlay import (
    best_match_structure,
    magic_signature,
    score_structure_at,
    structure_sizes,
)

logger = logging.getLogger("memdiver.algorithms.structure_scan")

_SCAN_WINDOW = 32
# Minimum entropy to consider a region as potential key material: the
# window-aware default (4.5 at 32; the former 6.5 was unreachable, max 5.0).
_ENTROPY_THRESHOLD = default_entropy_threshold(_SCAN_WINDOW)

# --- span tolerance (window-edge effects) ----------------------------------
# A region's covered span is [first window start, last window start + W).
# * Above: every window of the region overlaps the structure or is joined to
#   it, and a window overlapping it by >= 1 byte starts at most W - 1 bytes
#   before it / ends at most W - 1 bytes after it, so span <= S + 2 (W - 1).
#   How far it really extends depends on the neighbours: next to zeros a
#   window needs ~26 random bytes to reach 4.5 (6 bytes per side); next to
#   pointers / text up to ~14 per side. Measured on heap-like data with planted
#   32..72-byte keys (20 x 200 keys each): span - S in [1, 38], 99th pct <= 35.
# * Below: random windows reach 4.5 99.98% of the time; an edge window of the
#   structure that misses shortens the region by a few bytes. W / 4 allows it.
_SPAN_BELOW = _SCAN_WINDOW // 4
_SPAN_ABOVE = 2 * (_SCAN_WINDOW - 1)
#: Spans up to S + this get shape fit 1.0 (the measured range); the fit then
#: falls linearly to 0.5 at S + _SPAN_ABOVE and S - _SPAN_BELOW.
_SPAN_TYPICAL = _SCAN_WINDOW + 6
#: Edge blocks that must look random at both ends of a probed window.
_EDGE_BLOCK = 8
#: Collision count of a random window stays within its Poisson quantile.
_COLLISION_QUANTILE = 0.999
#: Start-offset grids probed in order (see ``_best_probe``).
_ALIGNMENT_TIERS = (8, 4, 1)

# --- bounds ----------------------------------------------------------------
#: Global match cap (``truncated`` in metadata once reached).
MAX_MATCHES = 4096
#: Bytes per overview view (bounds the regions held at once: one per 32 bytes
#: at worst), and the overlap between views (> any region we scan, > join gap
#: + window, so owned regions are seen whole).
_CHUNK_BYTES = 1 << 20
_CHUNK_OVERLAP = 4096
#: Overview read slab and per-worker sub-slab (bounds the estimate scratch).
_OVERVIEW_SLAB_BYTES = 2 << 20
_OVERVIEW_SUBSLAB_POSITIONS = 1 << 16
#: Matches per magic structure (a magic repeated everywhere must not flood).
MAX_MAGIC_HITS = 1024
_MIN_CONSTRAINT_SCORE = 0.5


@dataclass
class _ScanState:
    """Matches and counters shared by the scan passes."""

    matches: List[Match] = field(default_factory=list)
    seen_offsets: set = field(default_factory=set)
    regions: int = 0
    candidate_regions: int = 0
    bulk_regions: int = 0
    bulk_bytes: int = 0
    bulk_end: int = 0
    magic_hits: int = 0
    truncated: bool = False

    def full(self) -> bool:
        return len(self.matches) >= MAX_MATCHES

    def add(self, match: Match) -> None:
        if self.full():
            self.truncated = True
            return
        self.seen_offsets.add(match.offset)
        self.matches.append(match)


@dataclass(frozen=True)
class _Probe:
    """The best offset found for one size inside one region."""

    offset: int
    size: int
    collisions: int


class StructureScanAlgorithm(BaseAlgorithm):
    """Identify known data structures in memory dumps.

    Strategy:
    1. Exact high-entropy regions; keep those whose span fits a structure size
    2. Probe a few edge-aligned offsets per candidate region
    3. Find magic-constrained structures by their magic bytes
    4. Score = shape fit x field constraint validation
    """

    name = "structure_scan"
    description = "Identify known data structures in memory"
    mode = UNKNOWN_KEY

    def estimate_working_set(self, size: int,
                             context: Optional[AnalysisContext] = None,
                             sample: Optional[Sequence[bytes]] = None) -> int:
        """One overview view (scratch + regions) + the capped matches.

        With a *sample*, the region density and the nonzero fraction are
        measured on small pieces of it (see ``working_set``); worst case
        otherwise.
        """
        pieces = working_set.region_sample_pieces(sample, _SCAN_WINDOW)
        density = None
        if pieces:
            regions = sum(len(_view_regions(memoryview(p), 0, len(p))) for p in pieces)
            density = regions / sum(len(p) for p in pieces)
        return working_set.structure_scan_bytes(
            size, _SCAN_WINDOW, _CHUNK_BYTES + 2 * _CHUNK_OVERLAP,
            _OVERVIEW_SLAB_BYTES, _OVERVIEW_SUBSLAB_POSITIONS, MAX_MATCHES,
            region_density=density,
            dense_fraction=working_set.dense_block_fraction(pieces))

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        if len(dump_data) < _SCAN_WINDOW:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"reason": "dump too small"},
            )

        library = get_structure_library()
        protocol = _infer_protocol(context.protocol_version)
        candidates = (library.list_by_protocol(protocol) if protocol
                      else library.list_all())
        state = _ScanState()

        self._magic_matches(dump_data, candidates, state)
        self._shape_matches(dump_data, candidates, state)

        matches = sorted(state.matches, key=lambda m: (m.offset, -m.length))
        overall = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=round(overall, 4),
            matches=matches,
            metadata=_result_metadata(library, state),
        )

    # -- magic-constrained structures ------------------------------------

    def _magic_matches(self, data, candidates: Sequence[StructureDef],
                       state: _ScanState) -> None:
        """Every occurrence of each structure's magic, scored in place."""
        for struct_def in candidates:
            signature = magic_signature(struct_def)
            if signature is None:
                continue
            field_offset, magic = signature
            hits = 0
            for position in _iter_find(data, magic):
                offset = position - field_offset
                if offset < 0 or offset in state.seen_offsets:
                    continue
                overlays, score = score_structure_at(data, offset, struct_def)
                if score < _MIN_CONSTRAINT_SCORE:
                    continue
                state.add(self._make_match(data, offset, struct_def, overlays, score))
                state.magic_hits += 1
                hits += 1
                if hits >= MAX_MAGIC_HITS or state.full():
                    state.truncated = True
                    break

    # -- entropy-shaped structures ----------------------------------------

    def _shape_matches(self, data, candidates: Sequence[StructureDef],
                       state: _ScanState) -> None:
        """One match per high-entropy region whose span fits a structure size."""
        by_size = _structures_by_size(candidates)
        if not by_size:
            return
        sizes = sorted(by_size, reverse=True)
        bulk_span = sizes[0] + _SPAN_ABOVE
        for start, stop, owned in _iter_regions(data):
            if state.full():
                state.truncated = True
                return
            span = stop - start
            if span > bulk_span:
                _account_bulk(state, start, stop, owned)
                continue
            if not owned:
                continue
            state.regions += 1
            self._scan_region(data, start, stop, sizes, by_size, state)

    def _scan_region(self, data, start: int, stop: int, sizes: Sequence[int],
                     by_size: Dict[int, StructureLibrary], state: _ScanState) -> None:
        span = stop - start
        fitting = [s for s in sizes if s - _SPAN_BELOW <= span <= s + _SPAN_ABOVE]
        if not fitting:
            return
        state.candidate_regions += 1
        probe = _best_probe(data, start, stop, fitting)
        if probe is None or probe.offset in state.seen_offsets:
            return
        chunk = bytes(data[probe.offset:probe.offset + probe.size])
        result = best_match_structure(chunk, 0, by_size[probe.size])
        if result is None or result[2] < _MIN_CONSTRAINT_SCORE:
            return
        struct_def, overlays, score = result
        fit = _shape_fit(span, probe)
        match = self._make_match(data, probe.offset, struct_def,
                                 _rebase(overlays, probe.offset), round(fit * score, 4),
                                 length=probe.size)
        match.metadata.update({
            "size_class": probe.size,
            "region_offset": start,
            "region_span": span,
            "shape_fit": round(fit, 4),
            "constraint_score": score,
            "candidate_structures": sorted(s.name for s in by_size[probe.size].list_all()),
        })
        state.add(match)

    @staticmethod
    def _make_match(
        dump_data: bytes, offset: int, struct_def, overlays, confidence: float,
        length: Optional[int] = None,
    ) -> Match:
        length = struct_def.total_size if length is None else length
        return Match(
            offset=offset,
            length=length,
            confidence=confidence,
            label=f"struct:{struct_def.name}",
            data=bytes(dump_data[offset:offset + length]),
            metadata={
                "structure_name": struct_def.name,
                "protocol": struct_def.protocol,
                "fields": [
                    {"name": o.field_name, "offset": o.offset,
                     "display": o.display, "valid": o.valid}
                    for o in overlays
                ],
            },
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _infer_protocol(version: str) -> str:
    """Protocol filter from ``context.protocol_version`` (unchanged rules)."""
    if version.startswith("TLS") or version in ("12", "13"):
        return "TLS"
    if version.startswith("SSH") or version == "2":
        return "SSH"
    return ""


def _result_metadata(library: StructureLibrary, state: _ScanState) -> Dict:
    return {
        "structures_checked": len(library.list_all()),
        "high_entropy_regions": state.regions + state.bulk_regions,
        "candidate_regions": state.candidate_regions,
        "skipped_bulk_regions": state.bulk_regions,
        "skipped_bulk_bytes": state.bulk_bytes,
        "magic_matches": state.magic_hits,
        "matches_found": len(state.matches),
        "truncated": state.truncated,
        "max_matches": MAX_MATCHES,
        "entropy_threshold": _ENTROPY_THRESHOLD,
        "window": _SCAN_WINDOW,
    }


def _structures_by_size(candidates: Sequence[StructureDef]) -> Dict[int, StructureLibrary]:
    """Constrained, magic-free structures grouped by each size they can take."""
    groups: Dict[int, StructureLibrary] = {}
    for struct_def in candidates:
        if magic_signature(struct_def) is not None:
            continue
        if not any(f.constraints for f in struct_def.fields):
            continue
        for size in structure_sizes(struct_def):
            if size > 0:
                groups.setdefault(size, StructureLibrary()).register(struct_def)
    return groups


def _account_bulk(state: _ScanState, start: int, stop: int, owned: bool) -> None:
    """Count an owned bulk region; add its not-yet-counted bytes (views overlap)."""
    if owned:
        state.bulk_regions += 1
    state.bulk_bytes += max(0, stop - max(start, state.bulk_end))
    state.bulk_end = max(state.bulk_end, stop)


def _iter_regions(data) -> Iterator[Tuple[int, int, bool]]:
    """``(start, stop, owned)`` covered byte spans of the high-entropy regions.

    Views ``[lo - overlap, hi + overlap)`` per ``_CHUNK_BYTES`` chunk; a
    region is *owned* by the view whose chunk holds its start, unless it
    touches the view's start (then it continues from the previous view).
    """
    size = len(data)
    view = memoryview(data)
    try:
        for lo in range(0, size, _CHUNK_BYTES):
            first = max(0, lo - _CHUNK_OVERLAP)
            last = min(size, lo + _CHUNK_BYTES + _CHUNK_OVERLAP)
            for start, stop in _view_regions(view, first, last):
                owned = lo <= start < lo + _CHUNK_BYTES and (start > first or first == 0)
                yield start, stop, owned
    finally:
        try:
            view.release()
        except BufferError:  # a numpy view still alive; freed with it
            pass


def _view_regions(view: memoryview, first: int, last: int) -> List[Tuple[int, int]]:
    overview = stream_entropy_overview(
        lambda offset, length: view[first + offset:first + offset + length],
        last - first, _SCAN_WINDOW, _ENTROPY_THRESHOLD,
        min_width=region_min_span(_SCAN_WINDOW, 1), buckets=1,
        slab_bytes=_OVERVIEW_SLAB_BYTES, subslab_positions=_OVERVIEW_SUBSLAB_POSITIONS,
        join_gap=region_join_gap(_SCAN_WINDOW, 1))
    return [(first + s, first + e + _SCAN_WINDOW - 1) for s, e, _ in overview.regions]


def _iter_find(data, needle: bytes) -> Iterator[int]:
    """Ascending offsets of *needle* in *data* (``find`` or chunked search)."""
    if hasattr(data, "find"):
        position = data.find(needle)
        while position != -1:
            yield position
            position = data.find(needle, position + 1)
        return
    step = _CHUNK_BYTES
    for lo in range(0, len(data), step):
        block = bytes(data[lo:lo + step + len(needle) - 1])
        position = block.find(needle)
        while position != -1 and position < step:
            yield lo + position
            position = block.find(needle, position + 1)


def _best_probe(data, start: int, stop: int, sizes: Sequence[int]) -> Optional[_Probe]:
    """Largest size with a random-looking window, best alignment tier first.

    Tiers (8-, then 4-aligned, then any start) come before size: next to a
    pointer or a single zero byte a window shifted by a few bytes can still
    look random at its edges, but a shifted window on the 8-byte grid has a
    whole neighbour word at an edge and fails. (None if nothing passes.)
    """
    lo = max(0, min(start, stop - max(sizes)))
    hi = min(len(data), max(stop, start + max(sizes)))
    block = bytes(data[lo:hi])
    for tier in _ALIGNMENT_TIERS:
        for size in sizes:
            first = max(lo, min(start, stop - size))
            last = min(hi - size, max(start, stop - size))
            probe = _probe_size(block, lo, _tier_offsets(first, last, tier), size)
            if probe is not None:
                return probe
    return None


def _tier_offsets(first: int, last: int, tier: int) -> range:
    """Starts in ``[first, last]`` on the *tier* grid but not on the next one
    (8 is the top tier; 4 skips multiples of 8; 1 skips multiples of 4)."""
    coarser = {8: 0, 4: 8, 1: 4}[tier]
    begin = -(-first // tier) * tier
    offsets = range(begin, last + 1, tier)
    if not coarser:
        return offsets
    return [o for o in offsets if o % coarser]


def _probe_size(block: bytes, base: int, offsets, size: int) -> Optional[_Probe]:
    """Best random-looking ``size``-byte window among *offsets*.

    Prefers 16-aligned starts; among equals, the most distinct bytes.
    """
    best: Optional[Tuple[Tuple[int, int], _Probe]] = None
    limit = _collision_limit(size)
    for offset in offsets:
        window = block[offset - base:offset - base + size]
        collisions = size - len(set(window))
        if collisions > limit or not _edges_look_random(window):
            continue
        rank = (int(offset % 16 == 0), -collisions)
        if best is None or rank > best[0]:
            best = (rank, _Probe(offset, size, collisions))
    return None if best is None else best[1]


def _edges_look_random(window: bytes) -> bool:
    edge = min(_EDGE_BLOCK, len(window) // 2)
    return _looks_random_block(window[:edge]) and _looks_random_block(window[-edge:])


def _looks_random_block(block: bytes) -> bool:
    """False for typical non-key bytes: repeats (zeros, padding, text), the
    ``00 00`` of a user-space pointer's high bytes, all-printable ASCII.

    A uniform random 8-byte block fails with probability ~0.5%.
    """
    if len(set(block)) < len(block) - 1 or b"\x00\x00" in block:
        return False
    return not all(0x20 <= b < 0x7F for b in block)


def _expected_collisions(size: int) -> float:
    """Mean of ``size - distinct`` for uniform random bytes (~S(S-1)/512)."""
    return size - 256.0 * (1.0 - (255.0 / 256.0) ** size)


@lru_cache(maxsize=64)
def _collision_limit(size: int) -> int:
    """Poisson quantile of the collision count of ``size`` random bytes."""
    mean = _expected_collisions(size)
    term = cumulative = math.exp(-mean)
    count = 0
    while cumulative < _COLLISION_QUANTILE:
        count += 1
        term *= mean / count
        cumulative += term
    return count


def _span_fit(span: int, size: int) -> float:
    """1.0 for the measured span range, falling linearly to 0.5 at the tolerance."""
    excess = span - size
    if 0 <= excess <= _SPAN_TYPICAL:
        return 1.0
    if excess > _SPAN_TYPICAL:
        return 1.0 - 0.5 * (excess - _SPAN_TYPICAL) / (_SPAN_ABOVE - _SPAN_TYPICAL)
    return 1.0 - 0.5 * (-excess) / _SPAN_BELOW


def _randomness_fit(probe: _Probe) -> float:
    """1.0 up to the random mean of collisions, 0.5 at the accepted limit."""
    mean = _expected_collisions(probe.size)
    limit = _collision_limit(probe.size)
    if probe.collisions <= mean or limit <= mean:
        return 1.0
    return 1.0 - 0.5 * (probe.collisions - mean) / (limit - mean)


def _shape_fit(span: int, probe: _Probe) -> float:
    return _span_fit(span, probe.size) * _randomness_fit(probe)


def _rebase(overlays, base: int):
    for overlay in overlays:
        overlay.offset += base
    return overlays
