"""Exact byte match algorithm - search for known secret bytes in dump."""

from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import KNOWN_KEY


class ExactMatchAlgorithm(BaseAlgorithm):
    """Search for exact secret byte sequences in memory dumps."""

    name = "exact_match"
    description = "Search for exact secret byte sequences"
    mode = KNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        matches = []

        for secret in context.secrets:
            needle = secret.secret_value
            start = 0
            while True:
                idx = dump_data.find(needle, start)
                if idx == -1:
                    break
                matches.append(Match(
                    offset=idx,
                    length=len(needle),
                    confidence=1.0,
                    label=secret.secret_type,
                    data=needle,
                    metadata={"secret_type": secret.secret_type},
                ))
                start = idx + 1

        found_types = set(m.label for m in matches)
        total_types = len(set(s.secret_type for s in context.secrets))
        confidence = len(found_types) / total_types if total_types > 0 else 0.0

        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=confidence,
            matches=matches,
            metadata={
                "total_secret_types": total_types,
                "found_secret_types": len(found_types),
                "found_types_list": sorted(found_types),
            },
        )
