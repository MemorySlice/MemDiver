"""Reusable Shannon entropy computation for TLS memory dump analysis.

Provides sliding-window entropy profiling with O(1) incremental updates
per step. Used by change_point detection and entropy visualization.

All functions are stdlib-only (math) with no external dependencies.
"""

import logging
import math
from typing import List, Tuple

logger = logging.getLogger("memdiver.entropy")


def entropy_from_freq(freq: list, total: int) -> float:
    """Compute Shannon entropy from byte frequency counts.

    Iterates over 256 frequency bins and applies the standard formula:
        H = -sum(p * log2(p)) for each p = count / total where count > 0

    Args:
        freq: List of 256 integer counts (one per byte value).
        total: Sum of all counts (window size).

    Returns:
        Entropy in bits per byte, in range [0.0, 8.0].
        Returns 0.0 when total is zero.
    """
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of raw byte data.

    Builds a full frequency table over the input and computes entropy
    in a single pass.

    Args:
        data: Arbitrary byte sequence.

    Returns:
        Entropy in bits per byte, in range [0.0, 8.0].
        Returns 0.0 for empty input.
    """
    length = len(data)
    if length == 0:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    return entropy_from_freq(freq, length)


def compute_entropy_profile(
    data: bytes, window: int = 32, step: int = 1
) -> List[Tuple[int, float]]:
    """Sliding-window entropy profile over byte data.

    Uses an incremental frequency table that adds the incoming byte and
    removes the outgoing byte at each step, keeping each step O(1)
    regardless of window size.

    For large dumps (e.g. 10 MB), use step=16 to produce ~625K sample
    points instead of ~10M.

    Args:
        data: Raw memory dump bytes.
        window: Sliding window size in bytes (default 32).
        step: Advance step in bytes (default 1).

    Returns:
        List of (offset, entropy) tuples, one per window position.
        Returns an empty list when data is shorter than the window.
    """
    data_len = len(data)
    if data_len < window:
        return []

    # Initialize frequency table for the first window.
    freq = [0] * 256
    for i in range(window):
        freq[data[i]] += 1

    profile: List[Tuple[int, float]] = []
    profile.append((0, entropy_from_freq(freq, window)))

    # Slide the window forward by 'step' bytes at a time.
    pos = step
    while pos <= data_len - window:
        # Incrementally update: remove bytes that left, add bytes that entered.
        old_start = pos - step
        new_end_start = pos + window - step
        for i in range(old_start, min(old_start + step, data_len)):
            freq[data[i]] -= 1
        for i in range(new_end_start, min(new_end_start + step, data_len)):
            freq[data[i]] += 1
        profile.append((pos, entropy_from_freq(freq, window)))
        pos += step

    return profile


def find_high_entropy_regions(
    profile: List[Tuple[int, float]],
    threshold: float = 7.5,
    min_width: int = 32,
) -> List[Tuple[int, int, float]]:
    """Find contiguous high-entropy regions in an entropy profile.

    Scans the profile for runs of consecutive points at or above the
    threshold, then filters by minimum width.

    Args:
        profile: Output of compute_entropy_profile -- list of
            (offset, entropy) tuples, assumed sorted by offset.
        threshold: Minimum entropy (bits/byte) to qualify as
            high-entropy. Default 7.5 targets near-random data.
        min_width: Minimum span (end - start) in bytes for a region
            to be reported. Default 32 (one AES-256 key length).

    Returns:
        List of (start_offset, end_offset, mean_entropy) tuples for
        each qualifying region. Offsets refer to the window start
        positions from the profile.
    """
    if not profile:
        return []

    regions: List[Tuple[int, int, float]] = []
    in_region = False
    region_start = 0
    entropy_sum = 0.0
    region_count = 0

    for offset, entropy in profile:
        if entropy >= threshold:
            if not in_region:
                in_region = True
                region_start = offset
                entropy_sum = 0.0
                region_count = 0
            entropy_sum += entropy
            region_count += 1
        else:
            if in_region:
                region_end = offset
                if region_end - region_start >= min_width and region_count > 0:
                    mean_entropy = entropy_sum / region_count
                    regions.append((region_start, region_end, mean_entropy))
                in_region = False

    # Close any region that extends to the end of the profile.
    if in_region and region_count > 0:
        last_offset = profile[-1][0]
        region_end = last_offset
        if region_end - region_start >= min_width:
            mean_entropy = entropy_sum / region_count
            regions.append((region_start, region_end, mean_entropy))

    return regions
