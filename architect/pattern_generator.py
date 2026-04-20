"""PatternGenerator - create wildcard patterns from hex regions."""

import logging
from typing import List, Optional, Tuple

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
