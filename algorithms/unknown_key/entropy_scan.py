"""Shannon entropy sliding window algorithm for detecting high-entropy key material."""

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY
from core.entropy import entropy_from_freq


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
        if not matches:
            return []
        matches.sort(key=lambda m: (m.offset, -m.length))
        merged = [matches[0]]
        for m in matches[1:]:
            prev = merged[-1]
            if m.offset < prev.offset + prev.length:
                if m.confidence > prev.confidence:
                    merged[-1] = m
            else:
                merged.append(m)
        return merged
