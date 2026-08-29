"""PatternGenerator - create wildcard patterns from hex regions."""

import logging
import math
from collections import Counter
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger("memdiver.architect.pattern_generator")


class PatternGenerator:
    """Generate wildcard byte patterns from a region and its static mask.

    Static bytes become exact match values; volatile bytes become
    wildcards (??). The result can be exported as YARA or JSON.
    """

    @staticmethod
    def generate(
        reference_bytes: bytes,
        static_mask: List[bool],
        name: str = "unnamed_pattern",
        min_static_ratio: float = 0.3,
    ) -> Optional[dict]:
        """Generate a pattern dict from reference bytes and static mask.

        Args:
            reference_bytes: Bytes from the reference dump.
            static_mask: Per-byte static/volatile flags.
            name: Pattern name.
            min_static_ratio: Minimum ratio of static bytes required.

        Returns:
            Pattern dict with hex_pattern, wildcard_pattern, metadata.
            None if insufficient static bytes.
        """
        if not reference_bytes or not static_mask:
            return None

        static_ratio = sum(static_mask) / len(static_mask)
        if static_ratio < min_static_ratio:
            logger.warning(
                "Pattern '%s': only %.1f%% static (need %.1f%%)",
                name, static_ratio * 100, min_static_ratio * 100,
            )
            return None

        # Build hex and wildcard patterns
        hex_parts = []
        wildcard_parts = []
        for i, byte_val in enumerate(reference_bytes):
            hex_parts.append(f"{byte_val:02x}")
            if i < len(static_mask) and static_mask[i]:
                wildcard_parts.append(f"{byte_val:02x}")
            else:
                wildcard_parts.append("??")

        pattern = {
            "name": name,
            "length": len(reference_bytes),
            "hex_pattern": " ".join(hex_parts),
            "wildcard_pattern": " ".join(wildcard_parts),
            "static_ratio": round(static_ratio, 4),
            "static_count": sum(static_mask),
            "volatile_count": len(static_mask) - sum(static_mask),
        }

        logger.info(
            "Generated pattern '%s': %d bytes, %.1f%% static",
            name, len(reference_bytes), static_ratio * 100,
        )
        return pattern

    @staticmethod
    def find_anchors(
        static_mask: List[bool],
        min_anchor_length: int = 4,
    ) -> List[Tuple[int, int]]:
        """Find contiguous runs of static bytes that can serve as anchors.

        Args:
            static_mask: Per-byte static flags.
            min_anchor_length: Minimum consecutive static bytes for an anchor.

        Returns:
            List of (start_offset, length) tuples for anchor regions.
        """
        anchors = []
        start = None
        for i, is_static in enumerate(static_mask):
            if is_static:
                if start is None:
                    start = i
            else:
                if start is not None and (i - start) >= min_anchor_length:
                    anchors.append((start, i - start))
                start = None
        if start is not None and (len(static_mask) - start) >= min_anchor_length:
            anchors.append((start, len(static_mask) - start))
        return anchors

    @staticmethod
    def anchor_distinctiveness(
        reference_bytes: bytes,
        static_mask: List[bool],
        min_anchor_length: int = 4,
    ) -> Dict[str, Union[int, float]]:
        """Measure how DISTINCTIVE a pattern's static anchors actually are.

        ``min_static_ratio`` in :meth:`generate` answers "is there enough
        static material to build a rule from?". It cannot answer the question
        that decides whether the rule is useful: "do those static bytes say
        anything?" A window whose anchors are 128 zero bytes passes any static
        ratio and then matches thousands of positions in the very dump it came
        from.

        This is not hypothetical. On the real 8-dump OpenSSL TLS 1.2 corpus the
        48-byte master secret at offset 370,672 sits inside a run of zeros: at
        the default 64 bytes of context the resulting mask has 128 static bytes
        carrying exactly ONE distinct value, and the emitted rule matches 5,311
        positions in its own source dump.

        Only bytes inside a static RUN of at least *min_anchor_length* count —
        the same anchors :meth:`find_anchors` reports, because a lone static
        byte between two wildcards anchors nothing.

        Returns:
            ``distinct_bytes`` (how many different values the anchors carry),
            ``shannon_bits`` (their per-byte Shannon entropy, 0.0 for a single
            repeated value), ``longest_constant_run`` (the longest run of ONE
            repeated value within a single anchor — never spanning two anchors,
            which are not adjacent in the matched bytes) and ``static_bytes``
            (how many bytes were measured). All zero when there are no anchors.
        """
        anchors = PatternGenerator.find_anchors(static_mask, min_anchor_length)
        runs: List[List[int]] = []
        for start, length in anchors:
            run = list(reference_bytes[start:start + length])
            if run:
                runs.append(run)
        values = [b for run in runs for b in run]
        if not values:
            return {
                "distinct_bytes": 0,
                "shannon_bits": 0.0,
                "longest_constant_run": 0,
                "static_bytes": 0,
            }

        counts = Counter(values)
        total = len(values)
        shannon = -sum(
            (c / total) * math.log2(c / total) for c in counts.values()
        )
        longest = 0
        for run in runs:
            current = 1
            longest = max(longest, 1)
            for i in range(1, len(run)):
                current = current + 1 if run[i] == run[i - 1] else 1
                longest = max(longest, current)
        return {
            "distinct_bytes": len(counts),
            # max(0.0, ...) only to normalise the -0.0 a single-value Counter
            # produces; the sum is mathematically non-negative.
            "shannon_bits": round(max(0.0, shannon), 4),
            "longest_constant_run": longest,
            "static_bytes": total,
        }

    @staticmethod
    def infer_fields(
        variance: List[float],
        key_offset: int,
        key_length: int,
        threshold: float = 2000.0,
    ) -> List[dict]:
        """Segment variance into structural fields and dynamic regions.

        Walks the variance array and groups contiguous bytes by whether
        their variance is below *threshold* (static) or above (dynamic).
        The known key region is labeled ``key_material`` regardless of
        individual byte variance.

        Returns:
            List of field dicts with *offset*, *length*, *type*
            (``'static'``, ``'dynamic'``, or ``'key_material'``),
            *mean_variance*, and *label*.
        """
        if not variance:
            return []

        n = len(variance)
        key_end = key_offset + key_length

        # Assign per-byte role: key region overrides variance classification.
        roles: List[str] = []
        for i in range(n):
            if key_offset <= i < key_end:
                roles.append("key_material")
            elif float(variance[i]) <= threshold:
                roles.append("static")
            else:
                roles.append("dynamic")

        # Merge contiguous runs of the same role into fields.
        fields: List[dict] = []
        run_start = 0
        for i in range(1, n):
            if roles[i] != roles[run_start]:
                fields.append(_make_field(
                    variance, run_start, i, roles[run_start], fields,
                ))
                run_start = i
        fields.append(_make_field(
            variance, run_start, n, roles[run_start], fields,
        ))
        return fields


def _make_field(
    variance: List[float],
    start: int,
    end: int,
    role: str,
    existing: List[dict],
) -> dict:
    """Build one field dict and assign a sequential label."""
    length = end - start
    mean_var = sum(float(v) for v in variance[start:end]) / length
    if role == "key_material":
        label = "key"
    else:
        seq = sum(1 for f in existing if f["type"] == role)
        label = f"{role}_{seq}"
    return {
        "offset": start,
        "length": length,
        "type": role,
        "mean_variance": round(mean_var, 2),
        "label": label,
    }
