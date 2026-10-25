"""Key-sized high-entropy windows: a thin wrapper over ``unknown_key.entropy_scan``.

Reuses :class:`EntropyScanAlgorithm` unchanged. What it adds is key-finding defaults:
the symmetric key sizes 16/24/32/48/64 bytes, each scanned with its own window-aware
threshold (:func:`core.entropy.default_entropy_threshold`; a 16-byte window can never
reach the 32-byte window's 4.5 bits/byte), and a ``high_entropy_window`` label.
"""

from typing import Any, List, Optional, Sequence

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm
from memdiver.core.constants import UNKNOWN_KEY
from memdiver.core.entropy import default_entropy_threshold

KEY_WINDOW_SIZES = (16, 24, 32, 48, 64)
DEFAULT_STEP = 1


def _scan_window(data: Any, window: int, threshold: Optional[float], step: int) -> List[Match]:
    extra = {"window_sizes": [window], "step": step,
             "entropy_threshold": (default_entropy_threshold(window)
                                   if threshold is None else threshold)}
    result = EntropyScanAlgorithm().run(data, AnalysisContext("", "", "", extra=extra))
    for match in result.matches:
        match.label = "high_entropy_window"
        match.metadata["threshold"] = extra["entropy_threshold"]
    return result.matches


def find_high_entropy_windows(data: Any, window_sizes: Sequence[int] = KEY_WINDOW_SIZES,
                              threshold: Optional[float] = None,
                              step: int = DEFAULT_STEP) -> List[Match]:
    """High-entropy regions per key-sized window, ordered by offset.

    ``threshold=None`` picks the window-aware default per size; regions from
    different sizes are reported separately (``metadata["window_size"]``).
    """
    if not window_sizes or min(window_sizes) < 1 or step < 1:
        raise ValueError("window sizes and step must be >= 1")
    matches = [m for window in window_sizes
               for m in _scan_window(data, window, threshold, step)]
    return sorted(matches, key=lambda m: (m.offset, m.length))


class EntropyWindowAlgorithm(BaseAlgorithm):
    """Key-sized (16/24/32/48/64 byte) high-entropy window finder."""

    name = "entropy_window"
    description = "Key-sized high-entropy windows with window-aware thresholds"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        extra = context.extra
        matches = find_high_entropy_windows(
            dump_data, window_sizes=extra.get("window_sizes", KEY_WINDOW_SIZES),
            threshold=extra.get("entropy_threshold"), step=extra.get("step", DEFAULT_STEP))
        confidence = min(len(matches) / 10.0, 1.0) if matches else 0.0
        return AlgorithmResult(algorithm_name=self.name, confidence=confidence,
                               matches=matches, metadata={"windows": len(matches)})

    def estimate_working_set(self, size: int, context: Optional[AnalysisContext] = None,
                             sample: Optional[Sequence[bytes]] = None) -> int:
        """Worst case over the window sizes, as the underlying scan estimates it."""
        extra = context.extra if context is not None else {}
        sizes = extra.get("window_sizes", KEY_WINDOW_SIZES)
        scan = EntropyScanAlgorithm()
        step_extra = {"step": extra.get("step", DEFAULT_STEP)}
        return max(scan.estimate_working_set(
            size, AnalysisContext("", "", "", extra={**step_extra, "window_sizes": [w]}), sample)
            for w in sizes)
