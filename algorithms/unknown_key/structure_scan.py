"""Structure scanning algorithm — identify known data structures in memory.

Combines entropy analysis with structure overlay matching to find regions
that match known cryptographic or protocol-specific memory layouts.
"""

import logging
from typing import List

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY
from core.entropy import compute_entropy_profile, find_high_entropy_regions
from core.structure_library import get_structure_library
from core.structure_overlay import best_match_structure

logger = logging.getLogger("memdiver.algorithms.structure_scan")

# Minimum entropy to consider a region as potential key material
_ENTROPY_THRESHOLD = 6.5
_SCAN_WINDOW = 32
_SCAN_STEP = 16


class StructureScanAlgorithm(BaseAlgorithm):
    """Identify known data structures in memory dumps.

    Strategy:
    1. Compute entropy profile to find high-entropy regions
    2. At each candidate offset, try structure overlay matching
    3. Score based on field constraint validation
    """

    name = "structure_scan"
    description = "Identify known data structures in memory"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        if len(dump_data) < _SCAN_WINDOW:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                matches=[],
                metadata={"reason": "dump too small"},
            )

        library = get_structure_library()
        protocol = ""
        # Infer protocol from context if available
        version = context.protocol_version
        if version.startswith("TLS") or version in ("12", "13"):
            protocol = "TLS"
        elif version.startswith("SSH") or version == "2":
            protocol = "SSH"

        # Step 1: Find high-entropy regions
        profile = compute_entropy_profile(
            dump_data, window=_SCAN_WINDOW, step=_SCAN_STEP
        )
        high_regions = find_high_entropy_regions(
            profile, threshold=_ENTROPY_THRESHOLD
        )

        matches: List[Match] = []
        seen_offsets: set = set()

        # Step 2: Try structure matching at each high-entropy region start
        for start, end, _mean_entropy in high_regions:
            for offset in range(start, min(end, len(dump_data)), _SCAN_STEP):
                if offset in seen_offsets:
                    continue
                result = best_match_structure(dump_data, offset, library, protocol)
                if result is None:
                    continue
                struct_def, overlays, confidence = result
                if confidence < 0.5:
                    continue
                seen_offsets.add(offset)
                matches.append(self._make_match(
                    dump_data, offset, struct_def, overlays, confidence,
                ))

        # Also try at offset 0 and regular intervals (structures may
        # not reside in high-entropy regions)
        for offset in range(0, min(len(dump_data), 1024), 64):
            if offset in seen_offsets:
                continue
            result = best_match_structure(dump_data, offset, library, protocol)
            if result and result[2] >= 0.5:
                struct_def, overlays, confidence = result
                seen_offsets.add(offset)
                matches.append(self._make_match(
                    dump_data, offset, struct_def, overlays, confidence,
                ))

        overall = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=round(overall, 4),
            matches=matches,
            metadata={
                "structures_checked": len(library.list_all()),
                "high_entropy_regions": len(high_regions),
                "matches_found": len(matches),
            },
        )

    @staticmethod
    def _make_match(
        dump_data: bytes, offset: int, struct_def, overlays, confidence: float,
    ) -> Match:
        return Match(
            offset=offset,
            length=struct_def.total_size,
            confidence=confidence,
            label=f"struct:{struct_def.name}",
            data=dump_data[offset:offset + struct_def.total_size],
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
