"""User-defined regex pattern scanning algorithm."""

import re
from typing import List

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
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

            for m in compiled.finditer(dump_data):
                matched_bytes = m.group()
                matches.append(Match(
                    offset=m.start(),
                    length=len(matched_bytes),
                    confidence=1.0,
                    label=pattern_name,
                    data=matched_bytes,
                ))

        total = len(matches)
        confidence = min(total / 10.0, 1.0) if total > 0 else 0.0

        metadata = {
            "patterns_provided": len(user_patterns),
            "total_matches": total,
        }
        if skipped_patterns:
            metadata["skipped_patterns"] = skipped_patterns

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=confidence,
            matches=matches,
            metadata=metadata,
        )
