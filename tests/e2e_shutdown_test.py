"""End-to-end cover for the shutdown defect that forced ``kill -9``.

Killing the running server printed::

    resource_tracker: There appear to be 5 leaked semaphore objects to clean up
    [1]  46494 killed     memdiver

The five semaphores are the fingerprint of exactly one un-finalized
``ProcessPoolExecutor`` (``_call_queue`` contributes three, ``_result_queue``
two) -- the app-lifetime pool in ``api/services/task_manager.py``. They leaked
because SIGKILL skips every ``atexit`` handler, and SIGKILL was only ever needed
because a graceful shutdown could not finish.

These two tests drive the REAL console entry point, which is the only place all
the pieces meet: the CLI, uvicorn's signal handling and graceful-shutdown
timeout, the FastAPI lifespan, and the TaskManager teardown. The unit tests pin
the individual mechanisms; this pins that they add up.

Marked ``e2e`` (deselected by default, run with ``pytest -m e2e``) because it
spawns a live backend, following the convention of the other ``e2e_*_test.py``
modules. It needs no browser.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests._paths import REPO_ROOT
from tests._pymp import assert_no_new_pymp_dirs, pymp_dirs

pytestmark = pytest.mark.e2e

# Generous: a healthy shutdown is ~1s, and uvicorn's graceful window is 10s.
# Anything approaching this means the hang is back.
SHUTDOWN_DEADLINE_S = 40.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_server(tmp_path: Path, port: int) -> subprocess.Popen:
    """Launch the real ``memdiver web`` entry point and wait until it answers."""
    env = {
        **os.environ,
        "MEMDIVER_TASK_ROOT": str(tmp_path / "tasks"),
        "MEMDIVER_PORT": str(port),
        "PYTHONUNBUFFERED": "1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "memdiver.cli", "web", "--port", str(port)],
        cwd=str(REPO_ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early: {proc.communicate()[1]}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2):
                return proc
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    proc.kill()
    raise RuntimeError("server never became healthy")


def _kill_leftovers(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=10)


def test_sigint_shuts_down_without_leaking_semaphores(tmp_path: Path):
    """Ctrl-C returns promptly and leaks nothing.

    Before the fix this hung forever: the TaskManager parked threads of
    asyncio's DEFAULT executor, and ``loop.shutdown_default_executor()`` joins
    those with no timeout on Python 3.11.
    """
    before = pymp_dirs()
    proc = _start_server(tmp_path, _free_port())
    try:
        proc.send_signal(signal.SIGINT)
        started = time.monotonic()
        try:
            _, stderr = proc.communicate(timeout=SHUTDOWN_DEADLINE_S)
        except subprocess.TimeoutExpired:
            pytest.fail(
                "server did not exit within "
                f"{SHUTDOWN_DEADLINE_S}s of SIGINT -- the shutdown hang is back"
            )
        assert time.monotonic() - started < SHUTDOWN_DEADLINE_S
        assert "leaked semaphore" not in stderr, stderr[-3000:]
    finally:
        _kill_leftovers(proc)

    # The Manager process must be gone with its temp dir, not orphaned.
    assert_no_new_pymp_dirs(before)


def test_sigkill_leaves_no_orphaned_manager(tmp_path: Path):
    """Even an ungraceful kill strands nothing -- no atexit handler can do this.

    This is the parent-death watchdog (``core/process_guard.py``) proven through
    the real entry point rather than in isolation. Before it, a hard kill
    orphaned the Manager server forever: it is not a daemon process and
    ``Server.serve_forever`` has no parent check. Eight such orphans, up to 18
    days old, and 147 stale temp dirs had accumulated on the dev machine.
    """
    before = pymp_dirs()
    proc = _start_server(tmp_path, _free_port())
    try:
        spawned = pymp_dirs() - before
        assert spawned, "expected the server to start a Manager with a temp dir"

        proc.kill()  # SIGKILL: no handler in the parent can run
        proc.wait(timeout=10)

        # An orphaned Manager surviving SIGKILL of its parent is the whole
        # point of the watchdog; it shows up here as a dir that never goes.
        assert_no_new_pymp_dirs(before)
    finally:
        _kill_leftovers(proc)
