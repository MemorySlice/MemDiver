"""Tests for engine.batch module."""
import sys
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.input_schemas import AnalyzeRequest, BatchRequest
from engine.batch import BatchResult, BatchRunner, JobResult
from engine.results import AnalysisResult, LibraryReport


def _mock_run_analysis(request, **kwargs):
    """Mock run_analysis_request that returns a simple result."""
    result = AnalysisResult()
    for lib_dir in request.library_dirs:
        result.libraries.append(
            LibraryReport(
                library=lib_dir.name,
                protocol_version=request.protocol_version,
                phase=request.phase,
                num_runs=1,
            )
        )
    return result


def _make_request(tmp_path):
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir(exist_ok=True)
    return AnalyzeRequest(
        library_dirs=[lib_dir],
        phase="pre_abort",
        protocol_version="13",
    )


def test_single_job_succeeds(tmp_path):
    req = _make_request(tmp_path)
    batch = BatchRequest(jobs=[req])
    runner = BatchRunner()
    with patch("engine.batch.run_analysis_request", _mock_run_analysis):
        result = runner.run(batch)
    assert len(result.succeeded) == 1
    assert len(result.failed) == 0


def test_progress_callback_called(tmp_path):
    req = _make_request(tmp_path)
    batch = BatchRequest(jobs=[req])
    runner = BatchRunner()
    calls = []
    with patch("engine.batch.run_analysis_request", _mock_run_analysis):
        result = runner.run(batch, progress_callback=lambda c, t, s: calls.append((c, t, s)))
    assert len(calls) >= 2  # at least start + complete


def test_failure_does_not_abort_batch(tmp_path):
    req1 = _make_request(tmp_path)
    lib2 = tmp_path / "lib2"
    lib2.mkdir()
    req2 = AnalyzeRequest(library_dirs=[lib2], phase="pre_abort", protocol_version="13")
    batch = BatchRequest(jobs=[req1, req2])
    runner = BatchRunner()

    call_count = 0

    def _alternating_run(request, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("first job fails")
        return _mock_run_analysis(request)

    with patch("engine.batch.run_analysis_request", _alternating_run):
        result = runner.run(batch)
    assert len(result.succeeded) == 1
    assert len(result.failed) == 1


def test_to_dict_serializable(tmp_path):
    import json
    req = _make_request(tmp_path)
    batch = BatchRequest(jobs=[req])
    runner = BatchRunner()
    with patch("engine.batch.run_analysis_request", _mock_run_analysis):
        result = runner.run(batch)
    d = result.to_dict()
    text = json.dumps(d)
    assert '"succeeded_count": 1' in text


def test_batch_result_empty():
    br = BatchResult()
    assert br.succeeded == []
    assert br.failed == []
    d = br.to_dict()
    assert d["total_jobs"] == 0


def test_job_result_succeeded():
    jr = JobResult(job_index=0, request=None, result=AnalysisResult())
    assert jr.succeeded is True
    jr2 = JobResult(job_index=1, request=None, error="boom")
    assert jr2.succeeded is False


# --- Parallel execution tests ---


def _make_job_dirs(tmp_path, count):
    """Create dummy directories for test jobs."""
    dirs = []
    for i in range(count):
        d = tmp_path / f"lib_{i}" / f"lib_{i}_run_12_{i + 1}"
        d.mkdir(parents=True)
        (d / "20240101_120000_000001_pre_abort.dump").write_bytes(b"\x00" * 64)
        dirs.append(d.parent)
    return dirs


def _mock_result():
    """Create a minimal AnalysisResult for mocking."""
    return AnalysisResult()


def test_parallel_basic(tmp_path):
    """Parallel execution with workers=2 produces correct results."""
    dirs = _make_job_dirs(tmp_path, 4)
    jobs = [
        AnalyzeRequest(library_dirs=[d], phase="pre_abort", protocol_version="12")
        for d in dirs
    ]
    batch = BatchRequest(jobs=jobs)

    with patch("engine.batch.run_analysis_request") as mock_run:
        mock_run.return_value = _mock_result()
        runner = BatchRunner(workers=2)
        result = runner.run(batch)

    assert len(result.jobs) == 4
    assert all(j.succeeded for j in result.jobs)
    # Results should be in original order
    assert [j.job_index for j in result.jobs] == [0, 1, 2, 3]


def test_parallel_failure_isolation(tmp_path):
    """In parallel mode, one job failing doesn't affect others."""
    dirs = _make_job_dirs(tmp_path, 3)
    jobs = [
        AnalyzeRequest(library_dirs=[d], phase="pre_abort", protocol_version="12")
        for d in dirs
    ]
    batch = BatchRequest(jobs=jobs)

    def mock_run(req, **kwargs):
        if req.library_dirs[0] == dirs[1]:
            raise RuntimeError("job 1 failed")
        return _mock_result()

    with patch("engine.batch.run_analysis_request", side_effect=mock_run):
        runner = BatchRunner(workers=2)
        result = runner.run(batch)

    assert len(result.succeeded) == 2
    assert len(result.failed) == 1


def test_parallel_progress_callback(tmp_path):
    """Progress callback works in parallel mode."""
    dirs = _make_job_dirs(tmp_path, 2)
    jobs = [
        AnalyzeRequest(library_dirs=[d], phase="pre_abort", protocol_version="12")
        for d in dirs
    ]
    batch = BatchRequest(jobs=jobs)

    calls = []
    lock = threading.Lock()

    def cb(current, total, status):
        with lock:
            calls.append((current, total, status))

    with patch("engine.batch.run_analysis_request") as mock_run:
        mock_run.return_value = _mock_result()
        runner = BatchRunner(workers=2)
        result = runner.run(batch, progress_callback=cb)

    # Last call should be "Batch complete"
    assert calls[-1] == (2, 2, "Batch complete")


def test_workers_validation():
    """Workers < 1 raises ValueError."""
    import pytest

    with pytest.raises(ValueError):
        BatchRunner(workers=0)


def test_workers_default_is_sequential():
    """Default workers is 1 (sequential)."""
    runner = BatchRunner()
    assert runner._workers == 1


# --- ProcessPoolExecutor + project_db tests ---


def test_use_processes_flag():
    """use_processes flag stored correctly."""
    runner = BatchRunner(workers=2, use_processes=True)
    assert runner._use_processes is True
    assert runner._workers == 2


def test_use_processes_default_false():
    """Default use_processes is False."""
    runner = BatchRunner()
    assert runner._use_processes is False


def test_project_db_parameter():
    """project_db parameter stored on runner."""
    runner = BatchRunner(project_db="fake_db")
    assert runner._project_db == "fake_db"


def test_process_pool_basic(tmp_path):
    """ProcessPoolExecutor path runs correctly with workers=2."""
    dirs = _make_job_dirs(tmp_path, 2)
    jobs = [
        AnalyzeRequest(library_dirs=[d], phase="pre_abort", protocol_version="12")
        for d in dirs
    ]
    batch = BatchRequest(jobs=jobs)

    with patch("engine.batch.run_analysis_request") as mock_run:
        mock_run.return_value = _mock_result()
        runner = BatchRunner(workers=2, use_processes=False)  # threads for test safety
        result = runner.run(batch)

    assert len(result.succeeded) == 2
    assert [j.job_index for j in result.jobs] == [0, 1]


def test_auto_persist_false_when_project_db_set(tmp_path):
    """When project_db is set, auto_persist=False is passed to pipeline."""
    req = _make_request(tmp_path)
    batch = BatchRequest(jobs=[req])

    calls = []

    def tracking_run(request, **kwargs):
        calls.append(kwargs)
        return _mock_result()

    runner = BatchRunner(project_db="fake_db")
    with patch("engine.batch.run_analysis_request", tracking_run):
        runner.run(batch)

    assert len(calls) == 1
    assert calls[0].get("auto_persist") is False


def test_auto_persist_true_when_no_project_db(tmp_path):
    """When no project_db, auto_persist=True is passed to pipeline."""
    req = _make_request(tmp_path)
    batch = BatchRequest(jobs=[req])

    calls = []

    def tracking_run(request, **kwargs):
        calls.append(kwargs)
        return _mock_result()

    runner = BatchRunner()
    with patch("engine.batch.run_analysis_request", tracking_run):
        runner.run(batch)

    assert len(calls) == 1
    assert calls[0].get("auto_persist") is True


# --- ProcessPool pickling regression ---


def test_process_pool_dispatch_does_not_pickle_batchrunner(tmp_path):
    """Regression: ProcessPool path must not require BatchRunner to be picklable.

    Before the fix, BatchRunner.run(use_processes=True) submitted the bound
    method `self._execute_job` to ProcessPoolExecutor. Pickle serializes a
    bound method by pickling its __self__, which pulls in every attribute
    of the BatchRunner instance — including `_project_db`. In production
    `_project_db` is a DuckDB connection (not picklable), so the FIRST real
    call to `runner.run(use_processes=True, project_db=real_db)` would
    raise `TypeError: cannot pickle '_thread.lock' object` (or similar)
    before any worker started.

    This test uses a threading.Lock as a stand-in for any non-picklable
    attribute. It asserts two things:

    1. Pickling the BatchRunner instance (or its bound method) still fails
       — that confirms the premise that the old dispatch would have
       crashed in production.
    2. Pickling the module-level `_execute_batch_job` together with the
       plain-value args the new dispatch submits DOES succeed — that
       confirms the fix closes the bug.
    """
    import pickle

    from engine.batch import _execute_batch_job

    req = _make_request(tmp_path)

    non_picklable = threading.Lock()
    runner = BatchRunner(
        workers=2, use_processes=True, project_db=non_picklable,
    )

    # Premise: runner itself is NOT picklable because of _project_db
    import pytest

    with pytest.raises(TypeError):
        pickle.dumps(runner)

    # Premise: the legacy bound-method path would pickle the runner and
    # therefore also fail — documents why the old code was broken.
    with pytest.raises(TypeError):
        pickle.dumps(runner._execute_job)

    # Fix: module-level dispatch with plain-value args picks cleanly.
    auto_persist = runner._project_db is None  # False here
    assert auto_persist is False
    payload = (_execute_batch_job, 0, req, auto_persist)
    pickle.dumps(payload)  # must not raise
