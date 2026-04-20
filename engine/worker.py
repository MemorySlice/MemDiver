"""Module-level worker functions for ProcessPoolExecutor.

Functions here must be top-level (picklable with spawn start method).
They receive plain dicts, not dataclasses, to avoid __post_init__ validation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("memdiver.engine.worker")


def run_analysis_job(
    request_dict: Dict[str, Any],
    progress_queue=None,
    cancel_event=None,
) -> Dict[str, Any]:
    """Execute a single analysis job in a worker process.

    Args:
        request_dict: Serialized AnalyzeRequest fields (paths as strings).
        progress_queue: Optional multiprocessing.Queue for progress updates.
        cancel_event: Optional multiprocessing.Event for cancellation.

    Returns:
        Serialized AnalysisResult dict.
    """
    from pathlib import Path

    from core.input_schemas import AnalyzeRequest
    from engine.pipeline import AnalysisPipeline
    from engine.serializer import serialize_result

    if progress_queue:
        progress_queue.put({"status": "running", "step": "initializing", "pct": 0})

    # Reconstruct AnalyzeRequest from dict (avoids pickle of dataclass)
    request = AnalyzeRequest(
        library_dirs=[Path(d) for d in request_dict["library_dirs"]],
        phase=request_dict["phase"],
        protocol_version=request_dict["protocol_version"],
        keylog_filename=request_dict.get("keylog_filename", "keylog.csv"),
        template_name=request_dict.get("template_name", "Auto-detect"),
        max_runs=request_dict.get("max_runs", 10),
        normalize=request_dict.get("normalize", False),
        expand_keys=request_dict.get("expand_keys", True),
    )

    pipeline = AnalysisPipeline()
    result = pipeline.run(request)

    if progress_queue:
        progress_queue.put({"status": "completed", "pct": 100})

    return serialize_result(result)
