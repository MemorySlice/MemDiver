"""Incremental consensus-session state for the FastAPI API.

Each session wraps a ``ConsensusVector`` in its incremental mode: the caller
starts a session, folds dumps in one at a time, and finalizes when done.
State is kept in-process; a 30-minute idle TTL sweep drops orphaned sessions.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from memdiver.engine.consensus import ConsensusVector

logger = logging.getLogger("memdiver.api.services.consensus_session")

_DEFAULT_TTL_SECONDS = 30 * 60


@dataclass
class ConsensusSession:
    session_id: str
    size: int
    created_at: float
    last_used_at: float
    matrix: ConsensusVector
    finalized: bool = False
    dump_labels: List[str] = field(default_factory=list)

    def touch(self) -> None:
        self.last_used_at = time.time()

    def live_stats(self) -> Dict[str, Any]:
        """Mean / max variance and the top-5 offsets, computed slab by slab.

        Never materialises the full variance vector: each slab of at most
        ``PAIRWISE_LEAF`` positions is written into one reusable buffer
        (``m2 / n`` during an incremental build, a slice of the finalized
        vector afterwards). ``mean_variance`` and ``max_variance`` are
        bit-identical to ``variance.mean()`` / ``variance.max()`` (the slabs
        follow numpy's pairwise-summation tree). ``top_offsets`` is sorted by
        descending variance; ties are broken by ascending offset (the old
        ``argpartition`` tie order was unspecified).
        """
        source = _LiveVarianceSource.of(self.matrix)
        if source is None:
            return _live_stats_materialized(self.matrix.get_live_variance())
        if source.size == 0:
            return {"mean_variance": 0.0, "max_variance": 0.0, "top_offsets": []}
        return _live_stats_slabbed(source)


_TOP_K = 5


class _LiveVarianceSource:
    """Slab reader over the current variance without a full-size copy."""

    def __init__(self, size: int, dtype, read_into) -> None:
        self.size = size
        self.dtype = dtype
        self._read_into = read_into

    @classmethod
    def of(cls, matrix: ConsensusVector) -> "Optional[_LiveVarianceSource]":
        """Source for ``matrix``, or None when only the legacy path applies."""
        import numpy as np

        try:
            _mean, m2, n = matrix.welford_state()
        except RuntimeError:  # finalized: read the materialized vector
            variance = matrix.get_live_variance()
            if not (isinstance(variance, np.ndarray) and variance.ndim == 1
                    and variance.dtype in (np.float32, np.float64)):
                return None
            return cls(len(variance), variance.dtype,
                       lambda s, e, out: np.copyto(out, variance[s:e]))
        if m2.dtype != np.float32:
            return None
        if n == 0:
            return cls(len(m2), m2.dtype, lambda s, e, out: out.fill(0.0))
        return cls(len(m2), m2.dtype,
                   lambda s, e, out: np.divide(m2[s:e], n, out=out))

    def read(self, start: int, end: int, buf) -> Any:
        """Fill and return ``buf[:end - start]`` with variance[start:end]."""
        out = buf[: end - start]
        self._read_into(start, end, out)
        return out


def _live_stats_slabbed(source: _LiveVarianceSource) -> Dict[str, Any]:
    import numpy as np

    from memdiver.core.variance import PAIRWISE_LEAF, RunningTopK, pairwise_leaves_sum

    buf = np.empty(min(source.size, PAIRWISE_LEAF), dtype=source.dtype)
    top = RunningTopK(min(_TOP_K, source.size))
    peaks: List[float] = []

    def leaf_sum(start: int, end: int):
        slab = source.read(start, end, buf)
        peaks.append(slab.max())
        top.add_slab(slab, start)
        return np.add.reduce(slab)

    total = pairwise_leaves_sum(source.size, leaf_sum, PAIRWISE_LEAF)
    mean = total.dtype.type(total / source.size)  # same expression as np.mean
    return {
        "mean_variance": float(mean),
        "max_variance": float(max(peaks)),
        "top_offsets": [
            {"offset": offset, "variance": value} for offset, value in top.result()
        ],
    }


def _live_stats_materialized(variance) -> Dict[str, Any]:
    """Original whole-vector implementation (fallback for unusual dtypes)."""
    if len(variance) == 0:
        return {
            "mean_variance": 0.0,
            "max_variance": 0.0,
            "top_offsets": [],
        }
    import numpy as np

    k = min(5, len(variance))
    unsorted_top = np.argpartition(variance, -k)[-k:]
    top_idx = unsorted_top[np.argsort(variance[unsorted_top])[::-1]].tolist()
    return {
        "mean_variance": float(variance.mean()),
        "max_variance": float(variance.max()),
        "top_offsets": [
            {"offset": int(i), "variance": float(variance[i])} for i in top_idx
        ],
    }


class ConsensusSessionManager:
    """In-memory dict keyed by UUID with a lazy TTL sweep."""

    def __init__(self, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> None:
        self._sessions: Dict[str, ConsensusSession] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def begin(self, size: int, region_filter: Optional[str] = None) -> ConsensusSession:
        """Start an incremental session.

        ``region_filter`` (``to_note()`` string) is recorded on the matrix:
        every path folded in later is read through that view filter, and any
        window re-read of the finished build uses it too.
        """
        self._sweep()
        matrix = ConsensusVector()
        matrix.build_incremental(size)
        matrix.region_filter = region_filter
        session = ConsensusSession(
            session_id=str(uuid.uuid4()),
            size=size,
            created_at=time.time(),
            last_used_at=time.time(),
            matrix=matrix,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        logger.info("Consensus session started: %s size=%d", session.session_id, size)
        return session

    def register(self, matrix: ConsensusVector) -> ConsensusSession:
        """Store an already-built (one-shot) ``ConsensusVector`` and return its session.

        Unlike :meth:`begin` + :meth:`add_dump` (incremental Welford), this keeps
        the result of a one-shot ``build_from_sources`` so the
        ``/analysis/consensus`` endpoint's range queries no longer have to stash
        state on a process-wide singleton. Each build gets its own id, so
        concurrent clients can never read each other's results. The session is
        marked finalized; the idle TTL sweep reclaims it.
        """
        self._sweep()
        now = time.time()
        session = ConsensusSession(
            session_id=str(uuid.uuid4()),
            size=matrix.size,
            created_at=now,
            last_used_at=now,
            matrix=matrix,
            finalized=True,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        logger.info("Consensus build registered: %s size=%d",
                    session.session_id, matrix.size)
        return session

    def get(self, session_id: str) -> Optional[ConsensusSession]:
        self._sweep()
        with self._lock:
            session = self._sessions.get(session_id)
        if session is not None:
            session.touch()
        return session

    def add_dump(
        self, session_id: str, data: bytes, label: Optional[str] = None,
    ) -> Tuple[int, float, float]:
        session = self.get(session_id)
        if session is None:
            raise KeyError(session_id)
        if session.finalized:
            raise RuntimeError("session already finalized")
        num, mean_var, max_var = session.matrix.add_source(data)
        session.dump_labels.append(label or f"dump_{num}")
        return num, mean_var, max_var

    def finalize(self, session_id: str) -> ConsensusSession:
        session = self.get(session_id)
        if session is None:
            raise KeyError(session_id)
        if session.finalized:
            return session
        session.matrix.finalize()
        session.finalized = True
        return session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def _sweep(self) -> None:
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items()
                if (now - s.last_used_at) > self._ttl
            ]
            for sid in expired:
                self._sessions.pop(sid, None)
        if expired:
            logger.info("Swept %d expired consensus sessions", len(expired))


_default_manager: Optional[ConsensusSessionManager] = None
_default_manager_lock = threading.Lock()


def get_consensus_manager() -> ConsensusSessionManager:
    """FastAPI dependency accessor for the process-wide session manager."""
    global _default_manager
    if _default_manager is None:
        with _default_manager_lock:
            if _default_manager is None:
                _default_manager = ConsensusSessionManager()
    return _default_manager
