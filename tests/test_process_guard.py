"""Tests for core.process_guard — the parent-death watchdog itself.

Everything here runs in-process and in milliseconds. The real kill path is
covered by ``tests/test_guarded_sync_manager.py``; here the injected
``_getppid`` / ``_on_orphan`` seams stand in for it, because the production
``_on_orphan`` calls ``os._exit`` and would take the test runner with it.
"""

from __future__ import annotations

import pickle
import threading
from typing import Callable, List

import pytest

from memdiver.core.process_guard import (
    guard_child_process,
    install_parent_death_watchdog,
)

# Fast enough that the whole file runs in well under a second, slow enough that
# the watcher thread is not a busy loop.
FAST_POLL_S = 0.01
# Generous relative to FAST_POLL_S so a loaded machine cannot flake the suite.
FIRE_TIMEOUT_S = 2.0


def _ppid_sequence(values: List[int]) -> Callable[[], int]:
    """A fake ``os.getppid`` yielding ``values``, then repeating the last one."""
    remaining = iter(values)
    last = values[-1]

    def _getppid() -> int:
        return next(remaining, last)

    return _getppid


def test_watchdog_noop_when_ppid_stable():
    fired = threading.Event()
    thread = install_parent_death_watchdog(
        poll_interval=FAST_POLL_S,
        _getppid=lambda: 4242,
        _on_orphan=fired.set,
    )
    assert thread is not None
    # Several poll intervals' worth of an unchanged parent must not fire.
    assert not fired.wait(FAST_POLL_S * 10)


@pytest.mark.parametrize("new_ppid", [1, 7777])
def test_watchdog_fires_when_reparented(new_ppid: int):
    """Any ppid change is fatal, which guards `!= original` against `== 1`.

    Under a PR_SET_CHILD_SUBREAPER ancestor an orphan is adopted by that
    subreaper rather than by init, so a watchdog keyed on pid 1 would never
    fire. The parametrize IS the assertion that 1 is not special: reparenting
    to 7777 must be just as fatal as reparenting to init.
    """
    fired = threading.Event()
    # First value is the install-time snapshot of the original parent.
    install_parent_death_watchdog(
        poll_interval=FAST_POLL_S,
        _getppid=_ppid_sequence([4242, 4242, new_ppid]),
        _on_orphan=fired.set,
    )
    assert fired.wait(FIRE_TIMEOUT_S)


def test_watchdog_thread_is_daemon():
    """A non-daemon watcher would delay every graceful exit by a poll interval."""
    thread = install_parent_death_watchdog(
        poll_interval=FAST_POLL_S,
        _getppid=lambda: 4242,
        _on_orphan=lambda: None,
    )
    assert thread is not None
    assert thread.daemon is True


def test_install_never_raises_when_getppid_fails():
    """A watchdog that cannot be installed must not abort the child process."""

    def _broken_getppid() -> int:
        raise OSError("no parent for you")

    assert (
        install_parent_death_watchdog(
            poll_interval=FAST_POLL_S,
            _getppid=_broken_getppid,
            _on_orphan=lambda: None,
        )
        is None
    )


def test_watchdog_survives_a_failing_probe_without_firing():
    """A transient probe failure stops the watcher; it never guesses 'orphaned'."""
    fired = threading.Event()
    calls = {"n": 0}

    def _fails_after_install() -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return 4242
        raise OSError("probe exploded")

    install_parent_death_watchdog(
        poll_interval=FAST_POLL_S,
        _getppid=_fails_after_install,
        _on_orphan=fired.set,
    )
    assert not fired.wait(FAST_POLL_S * 10)


def test_guard_child_process_is_picklable():
    """Spawn must be able to ship the initializer by reference."""
    assert pickle.loads(pickle.dumps(guard_child_process)) is guard_child_process
