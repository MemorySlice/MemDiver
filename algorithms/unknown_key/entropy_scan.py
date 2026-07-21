"""Shannon entropy sliding window algorithm for detecting high-entropy key material."""

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.core.constants import UNKNOWN_KEY
from memdiver.core.entropy import entropy_from_freq


class EntropyScanAlgorithm(BaseAlgorithm):
    """Detect high-entropy regions that likely contain cryptographic key material."""

    name = "entropy_scan"
    description = "Shannon entropy sliding window scan for key-sized regions"
    mode = UNKNOWN_KEY

    DEFAULT_WINDOW_SIZES = [32, 48]
    DEFAULT_THRESHOLD = 4.5  # 7.0 requires near-perfect randomness; 4.5 catches real crypto keys
    DEFAULT_STEP = 1

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        window_sizes = context.extra.get("window_sizes", self.DEFAULT_WINDOW_SIZES)
        threshold = context.extra.get("entropy_threshold", self.DEFAULT_THRESHOLD)
        step = context.extra.get("step", self.DEFAULT_STEP)

        matches = []
        for window_size in window_sizes:
            found = self._scan_entropy(dump_data, window_size, threshold, step)
            matches.extend(found)

        matches = self._merge_overlapping(matches)

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=min(len(matches) / 10.0, 1.0) if matches else 0.0,
            matches=matches,
            metadata={
                "window_sizes": window_sizes,
                "threshold": threshold,
                "total_candidates": len(matches),
            },
        )

    def _scan_entropy(self, data: bytes, window_size: int, threshold: float,
                      step: int) -> list:
        matches = []
        if len(data) < window_size:
            return matches

        freq = [0] * 256
        for i in range(window_size):
            freq[data[i]] += 1

        for pos in range(0, len(data) - window_size + 1, step):
            if pos > 0:
                freq[data[pos - 1]] -= 1
                freq[data[pos + window_size - 1]] += 1

            entropy = entropy_from_freq(freq, window_size)
            if entropy >= threshold:
                matches.append(Match(
                    offset=pos,
                    length=window_size,
                    confidence=entropy / 8.0,
                    label=f"high_entropy_{window_size}B",
                    data=data[pos:pos + window_size],
                    metadata={"entropy": round(entropy, 4), "window_size": window_size},
                ))

        return matches

    @staticmethod
    def _merge_overlapping(matches: list) -> list:
        # Sibling interval-merge: differential.DifferentialAnalyzer._merge_nearby_runs.
        # Deliberately NOT shared -- the semantics diverge on both axes:
        #   * merge DECISION: here strict overlap only (gap tolerance 0, tracked
        #     via a running cluster_end); there gaps up to MAX_GAP_BYTES are
        #     bridged unless the gap contains an invariant byte.
        #   * merge ACTION: here the higher-confidence (then wider) Match is KEPT
        #     with its original bounds; there the (start, end) bounds are FUSED
        #     into a spanning interval.
        # Unifying would require a behaviour-changing merge, so they stay separate.
        if not matches:
            return []
        matches.sort(key=lambda m: (m.offset, -m.length))
        merged = [matches[0]]
        # ``cluster_end`` tracks the furthest right edge of the current run of
        # overlapping matches. Comparing against this (rather than only
        # ``merged[-1]``) ensures a later match that overlaps an earlier kept
        # interval is still merged even when it does not overlap the most
        # recently kept one, which previously inflated the match count.
        cluster_end = merged[0].offset + merged[0].length
        for m in matches[1:]:
            if m.offset < cluster_end:
                kept = merged[-1]
                # Per existing intent: keep the higher-confidence interval; on a
                # confidence tie keep the wider one. The match's own
                # offset/length/data are preserved unchanged (no synthesizing).
                if (m.confidence, m.length) > (kept.confidence, kept.length):
                    merged[-1] = m
                cluster_end = max(cluster_end, m.offset + m.length)
            else:
                merged.append(m)
                cluster_end = m.offset + m.length
        return merged
