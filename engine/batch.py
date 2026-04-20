"""Batch execution engine for headless CLI operations."""

import logging
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.input_schemas import AnalyzeRequest, BatchRequest
from engine.pipeline import AnalysisPipeline
from engine.results import AnalysisResult
from engine.serializer import serialize_result

logger = logging.getLogger("memdiver.engine.batch")


def run_analysis_request(request: AnalyzeRequest, auto_persist: bool = True) -> AnalysisResult:
    """Execute an AnalyzeRequest on a fresh pipeline."""
    pipeline = AnalysisPipeline(auto_persist=auto_persist)
    return pipeline.run(request)


@dataclass
class JobResult:
    """Result of a single batch job."""

    job_index: int
    request: AnalyzeRequest
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass
class BatchResult:
    """Aggregated result of a batch run."""

    jobs: List[JobResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    @property
    def succeeded(self) -> List[JobResult]:
        return [j for j in self.jobs if j.succeeded]

    @property
    def failed(self) -> List[JobResult]:
        return [j for j in self.jobs if not j.succeeded]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize batch result to JSON-compatible dict."""
        job_dicts = []
        succeeded_count = 0
        for job in self.jobs:
            d: Dict[str, Any] = {
                "job_index": job.job_index,
                "succeeded": job.succeeded,
                "duration_seconds": job.duration_seconds,
            }
            if job.result is not None:
                d["result"] = serialize_result(job.result)
            if job.error is not None:
                d["error"] = job.error
            job_dicts.append(d)
            if job.succeeded:
                succeeded_count += 1
        return {
            "jobs": job_dicts,
            "total_jobs": len(self.jobs),
            "succeeded_count": succeeded_count,
            "failed_count": len(self.jobs) - succeeded_count,
            "total_duration_seconds": self.total_duration_seconds,
        }


ProgressCallback = Callable[[int, int, Optional[str]], None]


def _execute_batch_job(
    idx: int, job: AnalyzeRequest, auto_persist: bool,
) -> JobResult:
    """Execute a single batch job with timing and error isolation.

    Module-level (not a bound method) so ProcessPoolExecutor can pickle it
    without dragging the BatchRunner instance — and therefore its
    `_project_db` attribute — across the process boundary. A DuckDB
    connection is not picklable, so submitting a bound method from a
    BatchRunner that holds a real ProjectDB would raise PicklingError on
    the first `use_processes=True` invocation.
    """
    job_start = time.monotonic()
    job_result = JobResult(job_index=idx, request=job)
    try:
        result = run_analysis_request(job, auto_persist=auto_persist)
        job_result.result = result
        logger.info("Job %d succeeded: %d hits", idx, result.total_hits)
    except Exception as exc:
        job_result.error = str(exc)
        logger.error("Job %d failed: %s", idx, exc)
    job_result.duration_seconds = time.monotonic() - job_start
    return job_result


class BatchRunner:
    """Execute a batch of analysis jobs with per-job error isolation."""

    def __init__(self, workers: int = 1, use_processes: bool = False, project_db=None):
        if workers < 1:
            raise ValueError("workers must be >= 1")
        self._workers = workers
        self._use_processes = use_processes
        self._project_db = project_db

    def _execute_job(self, idx: int, job: AnalyzeRequest) -> JobResult:
        """Thin wrapper around the module-level executor.

        Kept for backward compatibility with call sites / tests that expect
        `BatchRunner._execute_job` as an instance method. The actual work is
        delegated to the picklable module-level `_execute_batch_job`.
        """
        # When project_db is set, disable per-pipeline persistence so the
        # main process handles it after all jobs complete.
        auto_persist = self._project_db is None
        return _execute_batch_job(idx, job, auto_persist)

    def run(
        self,
        batch: BatchRequest,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> BatchResult:
        """Run all jobs in the batch.

        When workers=1, jobs run sequentially (original behavior).
        When workers>1, jobs run in parallel via ThreadPoolExecutor.
        """
        batch_result = BatchResult()
        batch_start = time.monotonic()
        total = len(batch.jobs)

        if self._workers == 1:
            for idx, job in enumerate(batch.jobs):
                if progress_callback:
                    progress_callback(idx, total, f"Starting job {idx}")
                jr = self._execute_job(idx, job)
                batch_result.jobs.append(jr)
        else:
            completed = 0
            lock = threading.Lock()
            Executor = ProcessPoolExecutor if self._use_processes else ThreadPoolExecutor
            # Dispatch via the module-level function so ProcessPool can pickle
            # the work unit without pickling `self` (which may hold a
            # non-picklable ProjectDB connection).
            auto_persist = self._project_db is None
            with Executor(max_workers=self._workers) as pool:
                futures = {
                    pool.submit(_execute_batch_job, idx, job, auto_persist): idx
                    for idx, job in enumerate(batch.jobs)
                }
                for future in as_completed(futures):
                    jr = future.result()
                    with lock:
                        completed += 1
                        batch_result.jobs.append(jr)
                        if progress_callback:
                            progress_callback(
                                completed, total,
                                f"Completed job {jr.job_index}",
                            )
            batch_result.jobs.sort(key=lambda j: j.job_index)

        batch_result.total_duration_seconds = time.monotonic() - batch_start

        # Persist results from main process when project_db provided
        if self._project_db and getattr(self._project_db, '_available', False):
            for jr in batch_result.succeeded:
                try:
                    self._project_db.persist_report(
                        serialize_result(jr.result) if jr.result else None,
                    )
                except Exception as e:
                    logger.warning("Failed to persist job %d: %s", jr.job_index, e)

        if progress_callback:
            progress_callback(total, total, "Batch complete")

        logger.info(
            "Batch complete: %d/%d succeeded in %.1fs",
            len(batch_result.succeeded),
            len(batch_result.jobs),
            batch_result.total_duration_seconds,
        )
        return batch_result
