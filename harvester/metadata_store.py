"""MetadataStore - aggregate metadata across runs using Polars."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.harvester.metadata_store")

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False

from core.models import RunDirectory


class MetadataStore:
    """Aggregate and query metadata across multiple runs.

    Uses Polars DataFrames for efficient filtering and aggregation
    of run metadata, sidecar data, and analysis results.
    """

    def __init__(self):
        self._records: List[Dict[str, Any]] = []
        self._df: Optional[object] = None

    def add_run(
        self,
        run: RunDirectory,
        sidecar: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a run directory with optional sidecar metadata."""
        record = {
            "library": run.library,
            "tls_version": run.tls_version,
            "run_number": run.run_number,
            "num_dumps": len(run.dumps),
            "num_secrets": len(run.secrets),
            "path": str(run.path),
        }
        if sidecar:
            for k, v in sidecar.items():
                if isinstance(v, (str, int, float, bool)):
                    record[f"meta_{k}"] = v
        self._records.append(record)
        self._df = None  # Invalidate cache

    def _ensure_df(self):
        """Build the Polars DataFrame if not cached."""
        if self._df is not None:
            return
        if not HAS_POLARS or not self._records:
            return
        self._df = pl.DataFrame(self._records)

    def get_runs_for_library(self, library: str) -> List[Dict]:
        """Get all run records for a specific library."""
        return [r for r in self._records if r["library"] == library]

    def summary(self) -> Dict[str, Any]:
        """Summary statistics across all registered runs."""
        if not self._records:
            return {"total_runs": 0}
        if not HAS_POLARS:
            return {
                "total_runs": len(self._records),
                "libraries": list(set(r["library"] for r in self._records)),
            }
        self._ensure_df()
        return {
            "total_runs": len(self._records),
            "libraries": self._df["library"].n_unique(),
            "total_dumps": self._df["num_dumps"].sum(),
            "total_secrets": self._df["num_secrets"].sum(),
        }

    def filter_by(self, **kwargs) -> List[Dict]:
        """Filter records by field values."""
        results = self._records
        for key, value in kwargs.items():
            results = [r for r in results if r.get(key) == value]
        return results
