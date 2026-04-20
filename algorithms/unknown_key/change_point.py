"""Entropy change-point detection using CUSUM for finding key-material plateaus."""

from bisect import bisect_left, bisect_right
from typing import Dict, List, Tuple

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY
from core.entropy import compute_entropy_profile


class ChangePointAlgorithm(BaseAlgorithm):
    """Detect key-material plateaus via CUSUM entropy change-point analysis.

    Three stages:
    1. Entropy profiling via sliding-window Shannon entropy.
    2. Gradient CUSUM edge detection on the first difference of the profile.
    3. Plateau extraction by pairing rising/falling edges that match
       expected key widths and exceed the entropy threshold.
    """

    name = "change_point"
    description = "Entropy change-point detection using CUSUM to find key-material plateaus"
    mode = UNKNOWN_KEY

    DEFAULT_WINDOW = 32
    DEFAULT_ENTROPY_THRESHOLD = 4.5
    DEFAULT_CUSUM_THRESHOLD = 0.8
    DEFAULT_DRIFT = 0.05
    DEFAULT_STEP = 16
    DEFAULT_PLATEAU_WIDTHS = [32, 48]

    @staticmethod
    def _cusum_change_points(
        profile: List[Tuple[int, float]],
        threshold: float = 0.8,
        drift: float = 0.05,
    ) -> List[Tuple[int, str, float]]:
        """Detect change points using gradient CUSUM.

        Reports the onset offset (not detection offset) for each edge.
        Returns list of (offset, direction, cusum_value) tuples where
        direction is "up" (rising) or "down" (falling).
        """
        if len(profile) < 2:
            return []

        s_high = 0.0
        s_low = 0.0
        change_points: List[Tuple[int, str, float]] = []

        # Track where the current accumulation run started so we can
        # report the onset offset rather than the detection offset.
        run_start_high = profile[0][0]
        run_start_low = profile[0][0]

        for i in range(1, len(profile)):
            offset = profile[i][0]
            gradient = profile[i][1] - profile[i - 1][1]

            # Track run-start: reset when the statistic was at zero.
            prev_s_high = s_high
            prev_s_low = s_low

            s_high = max(0.0, s_high + gradient - drift)
            s_low = max(0.0, s_low - gradient - drift)

            if prev_s_high == 0.0 and s_high > 0.0:
                run_start_high = offset
            if prev_s_low == 0.0 and s_low > 0.0:
                run_start_low = offset

            if s_high > threshold:
                change_points.append((run_start_high, "up", s_high))
                s_high = 0.0

            if s_low > threshold:
                change_points.append((run_start_low, "down", s_low))
                s_low = 0.0

        return change_points

    def _extract_plateaus(
        self,
        dump_data: bytes,
        profile: List[Tuple[int, float]],
        change_points: List[Tuple[int, str, float]],
        entropy_threshold: float,
        plateau_widths: List[int],
        window: int,
    ) -> List[Match]:
        """Pair rising/falling edges into key-sized high-entropy plateaus.

        Accepts pairs whose span matches a target key width (adjusted for
        window smearing) and whose mean entropy exceeds the threshold.
        """
        # Build an offset -> entropy lookup for fast slicing.
        entropy_lookup: Dict[int, float] = {off: ent for off, ent in profile}
        sorted_offsets = sorted(entropy_lookup.keys())

        # Pair consecutive up -> down transitions.
        pairs: List[Tuple[int, int, float, float]] = []
        i = 0
        while i < len(change_points) - 1:
            offset_up, direction_up, strength_up = change_points[i]
            offset_down, direction_down, strength_down = change_points[i + 1]

            if direction_up == "up" and direction_down == "down":
                pairs.append((offset_up, offset_down, strength_up, strength_down))
                i += 2
            else:
                i += 1

        width_tolerance = 16
        matches: List[Match] = []

        for start_off, end_off, strength_up, strength_down in pairs:
            profile_span = end_off - start_off
            if profile_span <= 0:
                continue

            best_key_width = 0
            best_distance = width_tolerance + 1
            for target_w in plateau_widths:
                expected_spans = [target_w, target_w + window - 1]
                for expected in expected_spans:
                    dist = abs(profile_span - expected)
                    if dist <= width_tolerance and dist < best_distance:
                        best_distance = dist
                        best_key_width = target_w

            if best_key_width == 0:
                continue

            # Compute mean entropy over the plateau region (binary search).
            lo = bisect_left(sorted_offsets, start_off)
            hi = bisect_right(sorted_offsets, end_off)
            segment_offsets = sorted_offsets[lo:hi]
            if not segment_offsets:
                continue

            segment_entropies = [entropy_lookup[off] for off in segment_offsets]
            mean_entropy = sum(segment_entropies) / len(segment_entropies)

            if mean_entropy < entropy_threshold:
                continue

            # The key material starts at the rising edge.  Extract
            # best_key_width bytes from that point.
            key_start = start_off
            key_len = min(best_key_width, len(dump_data) - key_start)
            plateau_data = dump_data[key_start:key_start + key_len]

            cusum_strength = (strength_up + strength_down) / 2.0
            confidence = min(mean_entropy / 8.0, 1.0) * min(cusum_strength / 3.0, 1.0)

            matches.append(
                Match(
                    offset=key_start,
                    length=key_len,
                    confidence=round(confidence, 4),
                    label=f"cusum_plateau_{key_len}B",
                    data=plateau_data,
                    metadata={
                        "entropy_mean": round(mean_entropy, 4),
                        "plateau_width": profile_span,
                        "estimated_key_width": best_key_width,
                        "cusum_strength": round(cusum_strength, 4),
                        "profile_segment": [
                            round(e, 4) for e in segment_entropies[:10]
                        ],
                    },
                )
            )

        return matches

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        """Run CUSUM change-point detection. Parameters from context.extra."""
        window = context.extra.get("window", self.DEFAULT_WINDOW)
        step = context.extra.get("step", self.DEFAULT_STEP)
        entropy_threshold = context.extra.get(
            "entropy_threshold", self.DEFAULT_ENTROPY_THRESHOLD
        )
        cusum_threshold = context.extra.get(
            "cusum_threshold", self.DEFAULT_CUSUM_THRESHOLD
        )
        drift = context.extra.get("drift", self.DEFAULT_DRIFT)
        plateau_widths = context.extra.get(
            "plateau_widths", self.DEFAULT_PLATEAU_WIDTHS
        )

        # Stage 1: compute entropy profile.
        profile = compute_entropy_profile(dump_data, window=window, step=step)

        # Stage 2: detect change points via gradient CUSUM.
        change_points = self._cusum_change_points(
            profile, threshold=cusum_threshold, drift=drift
        )

        # Stage 3: extract qualifying plateaus.
        matches = self._extract_plateaus(
            dump_data, profile, change_points, entropy_threshold, plateau_widths,
            window,
        )

        # Overall confidence scales with the number of plausible matches.
        overall_confidence = min(len(matches) / 10.0, 1.0) if matches else 0.0

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=round(overall_confidence, 4),
            matches=matches,
            metadata={
                "window": window,
                "step": step,
                "entropy_threshold": entropy_threshold,
                "cusum_threshold": cusum_threshold,
                "drift": drift,
                "plateau_widths": plateau_widths,
                "change_points_detected": len(change_points),
                "plateaus_matched": len(matches),
            },
        )
