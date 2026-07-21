"""Pattern-based algorithm that loads JSON structural patterns."""

import json
import logging
from pathlib import Path
from typing import List, Optional

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm
from memdiver.core.constants import UNKNOWN_KEY

logger = logging.getLogger(__name__)


class PatternMatchAlgorithm(BaseAlgorithm):
    """Match structural byte patterns around candidate key positions."""

    name = "pattern_match"
    description = "Structural pattern matching from JSON definitions"
    mode = UNKNOWN_KEY

    def __init__(self, patterns: Optional[List[dict]] = None):
        """Construct the algorithm.

        Args:
            patterns: Optional pre-loaded pattern definitions to inject. When
                ``None`` (the default), patterns are loaded from the shipped
                JSON files on disk exactly as before, so no-arg construction is
                unchanged. Injecting patterns skips disk I/O, which makes the
                algorithm testable with in-memory definitions.
        """
        self._patterns = []
        self._entropy_scanner = EntropyScanAlgorithm()
        if patterns is None:
            self._load_patterns()
        else:
            self._patterns = list(patterns)

    def _load_patterns(self):
        pattern_dir = Path(__file__).parent.parent / "patterns"
        for json_file in sorted(pattern_dir.glob("*.json")):
            try:
                with open(json_file) as f:
                    self._patterns.append(json.load(f))
            except (json.JSONDecodeError, IOError) as exc:
                logger.warning("Failed to load pattern file %s: %s", json_file, exc)
                continue

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        applicable = self._filter_patterns(context)
        if not applicable:
            return AlgorithmResult(
                algorithm_name=self.name,
                confidence=0.0,
                metadata={"reason": "no applicable patterns"},
            )

        matches = []

        for pattern in applicable:
            key_len = pattern["key_spec"]["length"]
            entropy_min = pattern["key_spec"].get("entropy_min", 7.0)

            # Shipped pattern JSONs specify entropy_min=7.0, which is
            # unreachable for real 32/48-byte keys (the theoretical max for an
            # n-byte window is log2(n) bits/byte, e.g. ~5.0 for 32 bytes), so
            # passing it straight through silently yields zero matches. Clamp
            # to the entropy scanner's own workable default so the shipped
            # configs can actually find keys.
            entropy_threshold = min(entropy_min, self._entropy_scanner.DEFAULT_THRESHOLD)

            entropy_ctx = AnalysisContext(
                library=context.library,
                tls_version=context.tls_version,
                phase=context.phase,
                extra={"window_sizes": [key_len], "entropy_threshold": entropy_threshold},
            )
            entropy_result = self._entropy_scanner.run(dump_data, entropy_ctx)

            for candidate in entropy_result.matches:
                score = self._check_structural(dump_data, candidate.offset, pattern)
                if score > 0:
                    matches.append(Match(
                        offset=candidate.offset,
                        length=candidate.length,
                        confidence=score,
                        label=pattern.get("name", "unknown_pattern"),
                        data=candidate.data,
                        metadata={
                            "pattern_name": pattern.get("name", ""),
                            "structural_score": score,
                            "entropy": candidate.metadata.get("entropy", 0),
                        },
                    ))

        confidence = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=confidence,
            matches=matches,
            metadata={
                "patterns_checked": len(applicable),
                "total_matches": len(matches),
            },
        )

    def _filter_patterns(self, context: AnalysisContext) -> list:
        applicable = []
        for p in self._patterns:
            app = p.get("applicable_to", {})
            libs = app.get("libraries", [])
            vers = app.get("protocol_versions", [])
            if libs and context.library not in libs:
                continue
            if vers and context.tls_version not in vers:
                continue
            applicable.append(p)
        return applicable

    @staticmethod
    def _check_structural(data: bytes, key_offset: int, pattern: dict) -> float:
        pat = pattern.get("pattern", {})
        total_checks = 0
        passed_checks = 0

        for region in ["before", "after"]:
            for rule in pat.get(region, []):
                total_checks += 1
                offset = rule["offset"]
                expected_hex = rule.get("bytes", "").replace(" ", "")
                mask_hex = rule.get("mask", "ff" * (len(expected_hex) // 2)).replace(" ", "")

                abs_offset = key_offset + offset
                if abs_offset < 0 or abs_offset + len(expected_hex) // 2 > len(data):
                    continue

                expected = bytes.fromhex(expected_hex)
                mask = bytes.fromhex(mask_hex)
                actual = data[abs_offset:abs_offset + len(expected)]

                if all((a & m) == (e & m) for a, e, m in zip(actual, expected, mask)):
                    passed_checks += 1

        return passed_checks / total_checks if total_checks > 0 else 0.0
