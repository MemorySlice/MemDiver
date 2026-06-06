"""User-defined regex pattern scanning algorithm."""

import re
from typing import List

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from algorithms.confidence import regex_specificity, density_penalty
from core.constants import UNKNOWN_KEY


class UserRegexAlgorithm(BaseAlgorithm):
    """Scan dump data using user-defined regex patterns."""

    name = "user_regex"
    description = "Scan with user-defined regex patterns"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        user_patterns = context.extra.get("user_patterns", [])

        matches: List[Match] = []
        skipped_patterns: List[str] = []

        dump_len = len(dump_data)
        per_pattern_confidences: List[float] = []
        matched_specificities: List[float] = []
        total_matched_bytes = 0

        for pattern_def in user_patterns:
            pattern_name = pattern_def.get("name", "unnamed")
            pattern_str = pattern_def.get("regex", "")

            if not pattern_str:
                skipped_patterns.append(f"{pattern_name}: empty regex")
                continue

            try:
                compiled = re.compile(pattern_str.encode())
            except re.error as exc:
                skipped_patterns.append(f"{pattern_name}: {exc}")
                continue

            pattern_bytes = 0
            pattern_match_count = 0

            for m in compiled.finditer(dump_data):
                matched_bytes = m.group()
                pattern_bytes += len(matched_bytes)
                pattern_match_count += 1
                matches.append(Match(
                    offset=m.start(),
                    length=len(matched_bytes),
                    # A regex hit is an exact match of the user's pattern;
                    # calibration lives at the result level.
                    confidence=1.0,
                    label=pattern_name,
                    data=matched_bytes,
                ))

            if pattern_match_count:
                specificity = regex_specificity(pattern_str)
                conf = min(0.5 + 0.5 * specificity, 1.0) * density_penalty(pattern_bytes, dump_len)
                per_pattern_confidences.append(conf)
                matched_specificities.append(specificity)
                total_matched_bytes += pattern_bytes

        total = len(matches)
        confidence = round(max(per_pattern_confidences), 4) if matches else 0.0

        metadata = {
            "patterns_provided": len(user_patterns),
            "total_matches": total,
            "specificity": max(matched_specificities) if matched_specificities else 0.0,
            "match_density": round(total_matched_bytes / dump_len, 4) if dump_len > 0 else 0.0,
        }
        if skipped_patterns:
            metadata["skipped_patterns"] = skipped_patterns

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=confidence,
            matches=matches,
            metadata=metadata,
        )
