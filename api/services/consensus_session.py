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

from engine.consensus import ConsensusVector

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
        variance = self.matrix.get_live_variance()
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

    def begin(self, size: int) -> ConsensusSession:
        self._sweep()
        matrix = ConsensusVector()
        matrix.build_incremental(size)
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
