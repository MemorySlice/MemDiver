"""Single conversion seam between API Pydantic request models and the core
request dataclasses.

Historically the analysis router inlined the field-by-field translation from
the validated Pydantic model (``api.models``) into either a core request
dataclass (``core.input_schemas``) or a JSON-friendly ``params`` dict for the
TaskManager ProcessPool. That inline mapping was duplicated per endpoint and
mirrored the core dataclass field list, so the two could silently drift.

This module owns that mapping in ONE place:

* :func:`to_analyze_request` / :func:`to_batch_request` build the canonical
  core dataclass from the Pydantic model. They are the typed conversion the
  goal asks for and the seam a drift test pins to
  ``core.input_schemas``. Note they run the dataclass ``__post_init__``
  validation (e.g. ``library_dirs`` must exist on disk).

* :func:`analyze_run_params` / :func:`batch_run_params` build the exact
  JSON-friendly ``params`` dict the analysis router hands to
  ``TaskManager.submit``. These are validation-free and byte-for-byte
  identical to what the router built inline, because the pool payload must
  stay unchanged and directory validation stays deferred to the worker.

Why two flavours: threading a core dataclass through the router ``/run`` and
``/batch`` endpoints would move the ``__post_init__`` directory validation
onto the request thread and would change the pickled pool payload — a wire /
behaviour change. So the router keeps using the dict builders here, and the
core converters exist for non-pool callers and to anchor the drift test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Union

from memdiver.api.models import (
    AnalyzeRequestAPI,
    BatchJobDTO,
    BatchRunRequest,
    ScanRequest as ScanRequestAPI,
)
from memdiver.core.input_schemas import AnalyzeRequest, BatchRequest, ScanRequest

# Both AnalyzeRequestAPI (the ``/run`` body) and BatchJobDTO (one batch job)
# expose the identical set of analysis fields, so a single converter serves
# both via attribute access.
AnalyzeLike = Union[AnalyzeRequestAPI, BatchJobDTO]


def to_analyze_request(model: AnalyzeLike) -> AnalyzeRequest:
    """Build the core :class:`AnalyzeRequest` from a validated Pydantic model.

    Maps every wire field to its core counterpart. ``library_dirs`` are the
    only type change (``list[str]`` -> ``list[Path]``). ``template`` is left at
    its dataclass default (``None``) because it is resolved server-side and is
    never part of the wire contract.

    Runs the dataclass ``__post_init__`` validation, so callers that must defer
    directory-existence checks to a worker should use :func:`analyze_run_params`
    instead.
    """
    return AnalyzeRequest(
        library_dirs=[Path(d) for d in model.library_dirs],
        phase=model.phase,
        protocol_version=model.protocol_version,
        keylog_filename=model.keylog_filename,
        template_name=model.template_name,
        max_runs=model.max_runs,
        normalize=model.normalize,
        expand_keys=model.expand_keys,
        algorithms=model.algorithms,
    )


def to_batch_request(model: BatchRunRequest) -> BatchRequest:
    """Build the core :class:`BatchRequest` from a validated ``BatchRunRequest``.

    Each ``BatchJobDTO`` is converted with :func:`to_analyze_request`. The
    ``workers`` field has no core counterpart (it is a pool-concurrency concern
    owned by the runner) and is intentionally dropped here.
    """
    return BatchRequest(
        jobs=[to_analyze_request(job) for job in model.jobs],
        output_format=model.output_format,
    )


def to_scan_request(model: ScanRequestAPI) -> ScanRequest:
    """Build the core :class:`ScanRequest` from the API :class:`ScanRequest`.

    Bridges the one deliberate naming difference between the wire model and the
    core dataclass: the wire field ``root`` maps to the core field
    ``dataset_root`` (``str`` -> ``Path``); ``keylog_filename`` / ``protocols``
    are 1:1. Runs the dataclass ``__post_init__`` (``dataset_root`` must be an
    existing directory), so — like the other core converters here — it is the
    typed seam a drift test pins to, not the API scan hot path (which streams
    ``root`` straight into ``tools.scan_dataset``).
    """
    return ScanRequest(
        dataset_root=Path(model.root),
        keylog_filename=model.keylog_filename,
        protocols=model.protocols,
    )


def analyze_run_params(model: AnalyzeRequestAPI, *, task_root: str) -> Dict[str, Any]:
    """Build the JSON-friendly ``params`` dict for ``POST /api/analysis/run``.

    Byte-for-byte identical to the dict the router built inline. Kept dict-based
    (rather than derived from :func:`to_analyze_request`) so the ProcessPool
    payload is unchanged and directory validation stays deferred to the worker.
    """
    return {
        "task_root": task_root,
        "library_dirs": list(model.library_dirs),
        "phase": model.phase,
        "protocol_version": model.protocol_version,
        "keylog_filename": model.keylog_filename,
        "template_name": model.template_name,
        "max_runs": model.max_runs,
        "normalize": model.normalize,
        "expand_keys": model.expand_keys,
        "algorithms": model.algorithms,
    }


def batch_run_params(model: BatchRunRequest, *, task_root: str) -> Dict[str, Any]:
    """Build the JSON-friendly ``params`` dict for ``POST /api/analysis/batch``.

    Byte-for-byte identical to the dict the router built inline: each job is
    serialized with ``model_dump()`` and ``workers`` is forwarded for the
    runner's inner concurrency. Directory validation stays deferred to the
    worker's per-job re-hydration.
    """
    return {
        "task_root": task_root,
        "jobs": [job.model_dump() for job in model.jobs],
        "output_format": model.output_format,
        "workers": model.workers,
    }
