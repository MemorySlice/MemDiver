"""Cooperative cancellation for background analysis tasks."""

from __future__ import annotations

import logging
import multiprocessing
from typing import Optional

logger = logging.getLogger("memdiver.engine.cancellation")


class AnalysisCancelled(Exception):
    """Raised when an analysis task is cancelled by the user."""


class CancellationToken:
    """Cooperative cancellation check for long-running operations.

    Workers receive a multiprocessing.Event; calling check() raises
    AnalysisCancelled if the event is set. The NULL_TOKEN singleton
    is used when cancellation is not needed (CLI, tests).
    """

    def __init__(self, event: Optional[multiprocessing.Event] = None):
        self._event = event

    def check(self) -> None:
        if self._event is not None and self._event.is_set():
            raise AnalysisCancelled("Task cancelled by user")

    @property
    def is_cancelled(self) -> bool:
        return self._event is not None and self._event.is_set()


NULL_TOKEN = CancellationToken(None)
