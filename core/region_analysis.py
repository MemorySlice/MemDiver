"""Pure Python investigation engine for analyzing specific memory regions.

Stdlib-only. Computes entropy, checks variance/hits, extracts strings.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from core.entropy import shannon_entropy
from core.strings import extract_strings

logger = logging.getLogger("memdiver.core.region_analysis")


@dataclass
class RegionReport:
    """Analysis report for a single memory region around an offset."""

    offset: int
    byte_value: int
    entropy: float
    entropy_level: str  # "low", "medium", "high", "random"
    variance_at_offset: Optional[float] = None
    variance_class: Optional[str] = None
    matching_secrets: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    neighborhood: bytes = b""


def _classify_entropy(entropy: float) -> str:
    """Classify entropy into human-readable level."""
    if entropy < 2.0:
        return "low"
    if entropy < 5.0:
        return "medium"
    if entropy < 7.0:
        return "high"
    return "random"


def _classify_variance(value: float) -> str:
    """Classify byte variance into a descriptive band."""
    if value < 1.0:
        return "static"
    if value < 50.0:
        return "low"
    if value < 200.0:
        return "medium"
    return "high"


def analyze_region(
    data: bytes,
    offset: int,
    window: int = 64,
    variance: Optional[list] = None,
    hits: Optional[list] = None,
) -> RegionReport:
    """Analyze a memory region around the given offset.

    Extracts a neighborhood, computes entropy, checks variance and
    hit coverage, and extracts printable strings.
    """
    half = window // 2
    start = max(0, offset - half)
    end = min(len(data), offset + half)
    neighborhood = data[start:end]

    entropy = shannon_entropy(neighborhood)
    byte_value = data[offset] if offset < len(data) else 0

    var_at = None
    var_class = None
    if variance is not None and offset < len(variance):
        var_at = float(variance[offset])
        var_class = _classify_variance(var_at)

    matching = []
    if hits:
        for hit in hits:
            if hit.offset <= offset < hit.offset + hit.length:
                matching.append(hit)

    return RegionReport(
        offset=offset,
        byte_value=byte_value,
        entropy=entropy,
        entropy_level=_classify_entropy(entropy),
        variance_at_offset=var_at,
        variance_class=var_class,
        matching_secrets=matching,
        strings=extract_strings(neighborhood),
        neighborhood=neighborhood,
    )


def find_pattern(
    data: bytes, pattern: bytes, max_results: int = 100,
) -> List[int]:
    """Find all offsets of a byte pattern in data, up to max_results."""
    if not pattern or not data:
        return []
    offsets: List[int] = []
    start = 0
    while len(offsets) < max_results:
        idx = data.find(pattern, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def parse_hex_pattern(text: str) -> Optional[bytes]:
    """Parse hex string ("48 65 6c" or "deadbeef") into bytes, or None."""
    if not (cleaned := text.strip()):
        return None
    try:
        return bytes.fromhex(cleaned.replace(" ", ""))
    except ValueError:
        return None
