"""Tests for core.process_guard.start_guarded_sync_manager.

Two things have to hold at once: the ``initializer=`` route must not disturb
the SyncManager the rest of the app relies on, and a manager whose owner is
SIGKILLed must take itself down AND remove its ``pymp-*`` directory. The last
test is the actual regression test for the orphan pile this module exists to
stop; the others are its guardrails.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from memdiver.core.process_guard import start_guarded_sync_manager
from tests._pymp import assert_no_new_pymp_dirs, pymp_dirs

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="parent-death watchdog and the pymp listener leak are POSIX-only",
)


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - alive but not ours
        return True
    return True


def test_guarded_manager_mints_queue_and_event():
    """The initializer hook must leave the inherited SyncManager registry intact."""
    manager = start_guarded_sync_manager(mp.get_context("spawn"))
    try:
        queue = manager.Queue()
        queue.put(1)
        assert queue.get() == 1

        event = manager.Event()
        event.set()
        assert event.is_set()
    finally:
        manager.shutdown()


def test_guarded_manager_leaves_no_pymp_dir():
    """A graceful shutdown still cleans up, watchdog or no watchdog."""
    before = pymp_dirs()
    manager = start_guarded_sync_manager(mp.get_context("spawn"))
    manager.shutdown()
    assert_no_new_pymp_dirs(before)


def test_orphaned_manager_self_terminates():
    """SIGKILL the owner; the manager must exit and take its temp dir with it."""
    child = subprocess.Popen(
        [sys.executable, "-m", "tests._orphan_child"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        text=True,
    )
    manager_pid = None
    try:
        assert child.stdout is not None
        handshake = json.loads(child.stdout.readline())
        manager_pid = handshake["manager_pid"]
        tempdir = handshake["tempdir"]
        assert _process_is_alive(manager_pid)
        assert os.path.isdir(tempdir)

        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if not _process_is_alive(manager_pid) and not os.path.exists(tempdir):
                break
            time.sleep(0.1)

        assert not _process_is_alive(manager_pid), (
            f"manager {manager_pid} outlived its SIGKILLed parent"
        )
        # The directory is the half a bare os._exit would have missed: the
        # process would be gone and the litter would remain.
        assert not os.path.exists(tempdir), f"orphan left {tempdir} behind"
    finally:
        if child.poll() is None:
            child.kill()
        # Never let a failing assertion above grow the orphan pile this module
        # exists to eliminate.
        if manager_pid is not None and _process_is_alive(manager_pid):
            try:
                os.kill(manager_pid, signal.SIGKILL)
            except OSError:
                pass
        if child.stdout is not None:
            child.stdout.close()
