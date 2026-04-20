"""Differential Memory Analysis algorithm (DPA-inspired).

Analyzes byte-position variance across N runs of the same TLS library at the
same lifecycle phase. Cryptographic key material produces high variance across
runs (different keys each time), while structural data (code, vtables, string
constants) remains stable. This contrast allows locating key-sized regions
without knowing the ground-truth secrets.
"""

from array import array
from pathlib import Path
from typing import Dict, List, Tuple

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY
from core.variance import (
    ByteClass,
    compute_variance,
    classify_variance,
    find_contiguous_runs,
    count_classifications,
)


class DifferentialAlgorithm(BaseAlgorithm):
    """Cross-run byte variance analysis to locate key-sized high-variance regions.

    Inspired by Differential Power Analysis (DPA), this algorithm computes the
    per-byte-position variance across multiple memory dumps captured at the same
    phase. Regions whose width matches typical TLS key lengths (32 or 48 bytes)
    and whose variance exceeds the pointer threshold are reported as key
    candidates.
    """

    name = "differential"
    description = "Cross-run byte variance analysis to locate key-sized high-variance regions"
    mode = UNKNOWN_KEY

    TARGET_KEY_LENGTHS = [32, 48]
    LENGTH_TOLERANCE = 8       # Accept regions within +/- this many bytes
    MAX_GAP_BYTES = 4          # Bridge gaps of up to this many non-candidate bytes

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        """Run differential analysis across multiple dumps at the same phase.

        Args:
            dump_data: Bytes of the primary dump (first run).
            context: Analysis context. ``context.extra["dump_paths"]`` must
                contain a list of :class:`~pathlib.Path` objects pointing to
                all N dumps for this phase (including the primary).

        Returns:
            AlgorithmResult with matched key-candidate regions and per-category
            byte classification counts in metadata.
        """
        dump_paths = self._resolve_dump_paths(context)
        if len(dump_paths) < 2:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"error": "need at least 2 dump paths for differential analysis"},
            )

        variance = self._compute_variance(dump_paths)
        classifications = classify_variance(variance)
        matches = self._extract_key_regions(dump_data, variance, classifications)

        classification_counts_map = count_classifications(classifications)
        overall_confidence = self._compute_confidence(matches, len(variance))

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=overall_confidence,
            matches=matches,
            metadata={
                "num_dumps": len(dump_paths),
                "analyzed_bytes": len(variance),
                "classification_counts": classification_counts_map,
                "total_candidates": len(matches),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_dump_paths(context: AnalysisContext) -> List[Path]:
        """Extract and validate dump paths from the analysis context."""
        raw_paths = context.extra.get("dump_paths", [])
        paths: List[Path] = []
        for p in raw_paths:
            path = Path(p) if not isinstance(p, Path) else p
            if path.is_file():
                paths.append(path)
        return paths

    @staticmethod
    def _compute_variance(dump_paths: List[Path]) -> array:
        """Compute per-byte-position variance across all dumps."""
        min_size = min(p.stat().st_size for p in dump_paths)
        if min_size == 0:
            return array("d")
        buffers = [p.read_bytes()[:min_size] for p in dump_paths]
        return compute_variance(buffers, min_size)

    def _extract_key_regions(
        self,
        primary_dump: bytes,
        variance: array,
        classifications: array,
    ) -> List[Match]:
        """Find contiguous key_candidate regions matching target key lengths.

        A region is accepted when its width falls within
        ``TARGET_KEY_LENGTHS[i] +/- LENGTH_TOLERANCE`` for any target length.

        Adjacent runs separated by small gaps (up to ``MAX_GAP_BYTES`` non-
        candidate bytes) are merged before width filtering. This prevents
        cryptographic key regions from being fragmented by individual bytes
        whose variance happens to fall slightly below the key_candidate
        threshold.
        """
        raw_regions = find_contiguous_runs(classifications, ByteClass.KEY_CANDIDATE)
        regions = self._merge_nearby_runs(raw_regions, self.MAX_GAP_BYTES, classifications)
        matches: List[Match] = []

        for start, end in regions:
            width = end - start
            if not self._width_matches_target(width):
                continue

            mean_var = sum(variance[start:end]) / width
            region_data = primary_dump[start:end] if start + width <= len(primary_dump) else b""
            region_counts = count_classifications(classifications[start:end])

            confidence = self._region_confidence(mean_var, width)

            matches.append(Match(
                offset=start,
                length=width,
                confidence=confidence,
                label=f"diff_key_candidate_{width}B",
                data=region_data,
                metadata={
                    "mean_variance": round(mean_var, 4),
                    "region_width": width,
                    "classification_counts": region_counts,
                },
            ))

        # Sort by confidence descending so the best candidates appear first.
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    # ------------------------------------------------------------------
    # Pure utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_nearby_runs(
        runs: List[Tuple[int, int]],
        max_gap: int,
        classifications: array,
    ) -> List[Tuple[int, int]]:
        """Merge runs separated by at most *max_gap* non-candidate bytes.

        Cryptographic key bytes are expected to have uniformly high variance,
        but with only ~10 samples individual bytes can randomly dip below the
        classification threshold.  Bridging small gaps prevents a single low-
        variance byte from splitting a 48-byte key into several tiny fragments.

        Gaps that contain any ``invariant`` byte (zero variance) are never
        bridged.  Invariant bytes are identical across all dumps and represent
        true structural boundaries (e.g. padding, length fields, zero-filled
        regions), so merging across them would combine unrelated high-variance
        regions into oversized candidates.

        Args:
            runs: Sorted (start, end) pairs from :func:`find_contiguous_runs`.
            max_gap: Maximum number of gap bytes to bridge between runs.
            classifications: Per-byte classification array used to detect
                invariant boundaries in gap regions.

        Returns:
            A new list of (start, end) pairs with nearby runs merged.
        """
        if not runs:
            return []
        merged: List[Tuple[int, int]] = [runs[0]]
        for start, end in runs[1:]:
            prev_start, prev_end = merged[-1]
            gap_size = start - prev_end
            if gap_size <= max_gap:
                # Never bridge across invariant (zero-variance) bytes -- they
                # are true structural boundaries between distinct regions.
                gap_has_invariant = any(
                    classifications[i] == ByteClass.INVARIANT
                    for i in range(prev_end, start)
                )
                if not gap_has_invariant:
                    merged[-1] = (prev_start, end)
                    continue
            merged.append((start, end))
        return merged

    def _width_matches_target(self, width: int) -> bool:
        """Check whether a region width is close enough to a target key length."""
        for target in self.TARGET_KEY_LENGTHS:
            if abs(width - target) <= self.LENGTH_TOLERANCE:
                return True
        return False

    @staticmethod
    def _region_confidence(mean_variance: float, width: int) -> float:
        """Compute a 0.0-1.0 confidence score for a candidate region.

        Higher variance and widths closer to 32/48 increase confidence.
        """
        # Variance component: saturates at ~8000 (max byte variance is 16256.25)
        var_score = min(mean_variance / 8000.0, 1.0)

        # Width component: reward exact key lengths, penalise deviation
        best_fit = min(abs(width - 32), abs(width - 48))
        width_score = max(1.0 - best_fit / 8.0, 0.0)

        return round(0.7 * var_score + 0.3 * width_score, 4)

    @staticmethod
    def _compute_confidence(matches: List[Match], total_bytes: int) -> float:
        """Compute an overall result confidence from individual matches."""
        if not matches or total_bytes == 0:
            return 0.0
        best_match_conf = max(m.confidence for m in matches)
        # Scale slightly by match count, capped at 1.0
        count_bonus = min(len(matches) / 20.0, 0.3)
        return round(min(best_match_conf + count_bonus, 1.0), 4)
