"""``engine.killable.run_killable`` with REAL spawned children."""

import os
import time

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.killable import run_killable

T = "tests._killable_targets:"
NEVER = lambda: False  # noqa: E731


def test_ok_result_and_kwargs():
    assert run_killable(T + "add", {"a": 2, "b": 3}, cancel=NEVER) == 5


def test_child_runs_in_another_process():
    assert run_killable(T + "pid", {}, cancel=NEVER) != os.getpid()


def test_large_result_arrives_whole():
    out = run_killable(T + "big_dict", {"n": 150_000}, cancel=NEVER)
    assert len(out) == 150_000 and out["sym_149999"] == 149_999


def test_progress_is_forwarded_in_order():
    seen = []
    assert run_killable(T + "with_progress", {"steps": 4}, cancel=NEVER,
                        on_progress=seen.append) == 4
    assert [m["stage"] for m in seen] == ["s0", "s1", "s2", "s3"]


def test_progress_not_passed_to_target_that_does_not_accept_it():
    assert run_killable(T + "add", {"a": 1, "b": 1}, cancel=NEVER, on_progress=print) == 2


def test_capability_error_round_trips():
    with pytest.raises(CapabilityError) as info:
        run_killable(T + "raises_capability", {}, cancel=NEVER)
    err = info.value
    assert (err.message, err.category, err.code, err.status) == (
        "bad thing", ErrorCategory.NOT_FOUND, "my.code", 404)
    assert err.details == {"k": [1, 2], "path": os.path.sep}


def test_generic_exception_becomes_worker_failed():
    with pytest.raises(CapabilityError) as info:
        run_killable(T + "raises_generic", {}, cancel=NEVER)
    err = info.value
    assert err.code == "worker_failed" and err.category is ErrorCategory.INTERNAL
    assert "ValueError" in err.message and "boom" in err.message
    assert err.details["exception_type"] == "ValueError"
    assert any("boom" in line for line in err.details["traceback_tail"])


def test_unimportable_target_is_worker_failed():
    with pytest.raises(CapabilityError) as info:
        run_killable("no_such_module_xyz:f", {}, cancel=NEVER)
    assert info.value.code == "worker_failed"


def test_crash_is_worker_crashed_with_exit_code():
    with pytest.raises(CapabilityError) as info:
        run_killable(T + "crash", {"code": 3}, cancel=NEVER)
    assert info.value.code == "worker_crashed" and info.value.details["exit_code"] == 3
    assert "3" in info.value.message


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_cancel_kills_a_sleeping_child_fast(tmp_path):
    pid_file = tmp_path / "pid"
    flipped = {}

    def cancel():  # flips once the child is demonstrably running its target
        if pid_file.exists() and pid_file.read_text():
            flipped.setdefault("t", time.monotonic())
        return "t" in flipped

    with pytest.raises(CapabilityError) as info:
        run_killable(T + "sleeps_and_reports_pid", {"path": str(pid_file)}, cancel=cancel)
    assert time.monotonic() - flipped["t"] < 1.5
    assert info.value.code == "cancelled" and info.value.category is ErrorCategory.PRECONDITION
    assert not _alive(int(pid_file.read_text()))


def test_cancel_latency_after_child_is_up():
    started = {}

    def cancel():
        started.setdefault("t", time.monotonic())
        return time.monotonic() - started["t"] > 1.0

    with pytest.raises(CapabilityError):
        run_killable(T + "sleeps", {"seconds": 60}, cancel=cancel)
    assert time.monotonic() - started["t"] < 1.5


def test_raising_cancel_callable_is_ignored():
    def broken():
        raise RuntimeError("manager gone")
    assert run_killable(T + "add", {"a": 1, "b": 2}, cancel=broken) == 3


def test_a_failing_progress_callback_does_not_abort_the_work():
    """A progress reporter that raises (e.g. a broken task queue) must not kill the job."""
    def boom(_info):
        raise RuntimeError("queue gone")
    assert run_killable(T + "with_progress", {"steps": 3}, cancel=NEVER, on_progress=boom) == 3
