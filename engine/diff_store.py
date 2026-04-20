"""DiffStore - Polars-based differential analysis of secret hits."""

import logging
import statistics
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger("memdiver.engine.diff_store")

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False
    logger.warning(
        "Polars not available — cross-dump variance, filtering, "
        "and correlation will use stdlib fallback"
    )

from .results import SecretHit


class DiffStore:
    """Aggregate and analyze secret hits across dumps using Polars.

    Provides cross-dump variance analysis, library correlation, and
    summary statistics using Polars DataFrames for efficient columnar ops.
    """

    def __init__(self):
        self._hits: List[Dict] = []
        self._df: Optional[object] = None

    def ingest_hits(self, hits: List[SecretHit]) -> None:
        """Add hits to the store for later analysis."""
        for h in hits:
            self._hits.append({
                "secret_type": h.secret_type,
                "offset": h.offset,
                "length": h.length,
                "library": h.library,
                "phase": h.phase,
                "run_id": h.run_id,
                "confidence": h.confidence,
                "dump_path": str(h.dump_path),
            })
        self._df = None  # Invalidate cached DataFrame
        logger.debug("Ingested %d hits, total: %d", len(hits), len(self._hits))

    def _ensure_df(self):
        """Build the Polars DataFrame if not already cached."""
        if self._df is not None:
            return
        if not HAS_POLARS:
            return
        if not self._hits:
            self._df = pl.DataFrame()
            return
        self._df = pl.DataFrame(self._hits)

    def cross_dump_variance(self) -> Dict[int, float]:
        """Compute per-offset variance across all dumps."""
        if not self._hits:
            return {}
        if not HAS_POLARS:
            return self._cross_dump_variance_fallback()
        self._ensure_df()
        if self._df.is_empty():
            return {}
        result = (
            self._df.lazy()
            .group_by("offset")
            .agg(pl.col("confidence").var().alias("variance"))
            .collect()
        )
        return dict(zip(result["offset"].to_list(), result["variance"].to_list()))

    def _cross_dump_variance_fallback(self) -> Dict[int, float]:
        """Stdlib fallback for per-offset sample variance."""
        groups: Dict[int, List[float]] = defaultdict(list)
        for h in self._hits:
            groups[h["offset"]].append(h["confidence"])
        return {
            offset: statistics.variance(vals) if len(vals) >= 2 else 0.0
            for offset, vals in groups.items()
        }

    def filter_key_candidates(self, min_count: int = 2) -> List[Dict]:
        """Keep offsets that appear in at least min_count different runs."""
        if not self._hits:
            return []
        if not HAS_POLARS:
            return self._filter_key_candidates_fallback(min_count)
        self._ensure_df()
        if self._df.is_empty():
            return []
        result = (
            self._df.lazy()
            .group_by("offset", "secret_type")
            .agg([
                pl.col("run_id").n_unique().alias("run_count"),
                pl.col("library").n_unique().alias("lib_count"),
            ])
            .filter(pl.col("run_count") >= min_count)
            .sort("offset")
            .collect()
        )
        return result.to_dicts()

    def _group_by_offset_secret(self) -> Dict[tuple, Dict[str, set]]:
        """Group hits by (offset, secret_type), collecting unique runs and libs."""
        groups: Dict[tuple, Dict[str, set]] = defaultdict(
            lambda: {"runs": set(), "libs": set()},
        )
        for h in self._hits:
            key = (h["offset"], h["secret_type"])
            groups[key]["runs"].add(h["run_id"])
            groups[key]["libs"].add(h["library"])
        return groups

    def _filter_key_candidates_fallback(self, min_count: int) -> List[Dict]:
        """Stdlib fallback: group by (offset, secret_type), count unique run_ids."""
        groups = self._group_by_offset_secret()
        result = []
        for (offset, secret_type), agg in sorted(groups.items()):
            if len(agg["runs"]) >= min_count:
                result.append({
                    "offset": offset,
                    "secret_type": secret_type,
                    "run_count": len(agg["runs"]),
                    "lib_count": len(agg["libs"]),
                })
        return result

    def correlate_across_libraries(self) -> List[Dict]:
        """Find offsets where the same secret appears across multiple libraries."""
        if not self._hits:
            return []
        if not HAS_POLARS:
            return self._correlate_across_libraries_fallback()
        self._ensure_df()
        if self._df.is_empty():
            return []
        result = (
            self._df.lazy()
            .group_by("offset", "secret_type")
            .agg([
                pl.col("library").n_unique().alias("lib_count"),
                pl.col("library").alias("libraries"),
            ])
            .filter(pl.col("lib_count") > 1)
            .sort("offset")
            .collect()
        )
        return result.to_dicts()

    def _correlate_across_libraries_fallback(self) -> List[Dict]:
        """Stdlib fallback: group by (offset, secret_type), count unique libraries."""
        groups = self._group_by_offset_secret()
        result = []
        for (offset, secret_type), agg in sorted(groups.items()):
            libs = agg["libs"]
            if len(libs) > 1:
                result.append({
                    "offset": offset,
                    "secret_type": secret_type,
                    "lib_count": len(libs),
                    "libraries": sorted(libs),
                })
        return result

    def summary_stats(self) -> Dict:
        """Aggregate statistics across all hits."""
        if not self._hits:
            return {"total_hits": 0}
        if not HAS_POLARS:
            offsets, libraries, types = set(), set(), set()
            for h in self._hits:
                offsets.add(h["offset"])
                libraries.add(h["library"])
                types.add(h["secret_type"])
            return {
                "total_hits": len(self._hits),
                "unique_offsets": len(offsets),
                "unique_libraries": len(libraries),
                "secret_types": len(types),
                "polars": False,
            }
        self._ensure_df()
        return {
            "total_hits": len(self._hits),
            "unique_offsets": self._df["offset"].n_unique(),
            "unique_libraries": self._df["library"].n_unique(),
            "secret_types": self._df["secret_type"].n_unique(),
        }
