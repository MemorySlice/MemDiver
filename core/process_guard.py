"""Parent-death watchdog for the helper processes MemDiver spawns.

``api.services.task_manager`` keeps two long-lived children alive for the whole
app lifetime: a spawn :class:`~concurrent.futures.ProcessPoolExecutor` and a
single :class:`multiprocessing.managers.SyncManager` that mints the progress
queues and cancel events crossing the process boundary. Both are *supposed* to
die with the server, and under a graceful shutdown they do.

Under ``SIGKILL`` they do not, and the Manager is the bad one. CPython starts
its server child without ``daemon=True`` and
:meth:`multiprocessing.managers.Server.serve_forever` has no parent-liveness
check, so a killed parent leaves a Manager that waits on an AF_UNIX socket
nobody will ever connect to again, forever. It is not even visibly wrong: the
process is idle and silent. Measured on one developer machine before this
module existed: 8 orphaned manager processes reparented away from their dead
owner, the oldest 18 days old, plus 147 abandoned ``pymp-*`` temp directories
under the per-user temp root, one per orphan that had ever been created.

The fix rides on the one public hook CPython already plumbs into that child.
:meth:`multiprocessing.managers.BaseManager.start` takes
``initializer``/``initargs`` and ``BaseManager._run_server`` calls the
initializer *inside the manager child, before the server object exists*.
:class:`~concurrent.futures.ProcessPoolExecutor` accepts the same pair. So one
module-level function, :func:`guard_child_process`, can be handed to both and
arm a watchdog thread that notices the parent's death and exits the child.

:meth:`multiprocessing.context.BaseContext.Manager` is hardcoded to
``SyncManager(ctx=self)`` followed by a bare ``start()`` and exposes no way to
pass an initializer, so :func:`start_guarded_sync_manager` inlines those two
lines rather than going through ``ctx.Manager()``.

This module lives in ``core`` because it has to be importable *early*, from a
freshly spawned interpreter, before any MemDiver subsystem is set up, and
``core`` is the only layer low enough to sit under every caller that needs it
(``app`` already pulls ``engine``). That is the whole reason; ``core`` is not
otherwise special here and is not dependency-free (``core.entropy`` and
``core.variance`` import numpy).

NOTE - measured import cost. Handing this module's function to a spawn
``initializer=`` does not give the child a cheap import. The child imports
``memdiver.core.process_guard``, which executes the parent ``memdiver``
package first, and ``memdiver/__init__.py`` is an eager public-API facade:
measured 0.48 s and 874 modules (numpy, polars, duckdb, ibis included), about
87 MB of RSS the Manager child would otherwise never pay. The root cause is
that facade, not this module; making it lazy (PEP 562 module ``__getattr__``)
is the fix if the cost ever starts to matter. Pool workers under ``engine``
already import ``memdiver``, so they pay nothing extra.
"""

from __future__ import annotations

import logging
import multiprocessing.util
import os
import sys
import threading
import time
from multiprocessing.managers import SyncManager
from typing import Callable, Optional

logger = logging.getLogger("memdiver.core.process_guard")

# Deliberately coarse. Nothing waits on this interval: unlike
# ``task_manager.DRAIN_POLL_S`` (which bounds a blocking ``queue.get`` a caller
# is sitting inside), this only bounds how long an ALREADY-orphaned child
# lingers before it notices, and by definition its parent is dead and nobody is
# blocked on the answer. The probe itself is free (``os.getppid()`` measured at
# 173 ns), but each armed watchdog is a periodic timer in an otherwise idle
# process - at 1 Hz, three of them (two pool workers plus the Manager) keep
# macOS App Nap off forever and show up as wakeups in ``powermetrics``. 5 s is a
# 5x cut in idle wakeups with no observable downside.
DEFAULT_POLL_INTERVAL_S: float = 5.0


def _terminate_orphan() -> None:
    """Exit the current process, running multiprocessing's exit finalizers first.

    The finalizer pass is not optional housekeeping. A bare :func:`os._exit`
    would end the orphan but leak its ``pymp-*`` directory, which is exactly
    half the observed damage: the process count would drop to zero and the
    directory litter would keep growing. That directory is removed by a
    :class:`multiprocessing.util.Finalize` registered inside
    ``multiprocessing.util.get_temp_dir()`` (the manager child calls it when it
    mints its own listener address), and that finalizer only ever runs via the
    ``atexit``-registered ``_exit_function``.

    ``os._exit`` rather than ``sys.exit`` because this runs on a watchdog
    thread, where ``SystemExit`` would unwind that thread and leave the server
    loop on the main thread running.
    """
    try:
        # Private, and absent from typeshed's stub, but it is the only
        # entry point that runs the atexit finalizer chain on demand.
        multiprocessing.util._exit_function()  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - best effort; exiting matters more
        logger.debug("orphan finalizers failed; exiting anyway", exc_info=True)
    os._exit(0)


def _watch_for_reparenting(
    original_ppid: int,
    poll_interval: float,
    getppid: Callable[[], int],
    on_orphan: Callable[[], None],
) -> None:
    """Poll the parent pid and invoke ``on_orphan`` once it changes."""
    while True:
        time.sleep(poll_interval)
        try:
            current_ppid = getppid()
        except Exception:  # pragma: no cover - defensive; a broken probe must
            # not take the child down, so stop watching instead of guessing.
            logger.debug("parent probe failed; watchdog stopping", exc_info=True)
            return
        # Compare against the ORIGINAL parent, never against pid 1. Under an
        # ancestor that has claimed PR_SET_CHILD_SUBREAPER (systemd user
        # sessions, container init shims, some IDE runners) an orphan is
        # reparented to that subreaper, not to init, so `== 1` would be a
        # watchdog that silently never fires on exactly the machines that need
        # it most. Any change of parent means the original one is gone.
        if current_ppid != original_ppid:
            on_orphan()
            return


def install_parent_death_watchdog(
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL_S,
    _getppid: Callable[[], int] = os.getppid,
    _on_orphan: Callable[[], None] = _terminate_orphan,
) -> Optional[threading.Thread]:
    """Arm a daemon thread that exits this process when its parent dies.

    Returns the watcher thread, or ``None`` if no watchdog was installed. The
    leading-underscore arguments are test seams: they let the reparenting and
    the exit be exercised in-process without a real kill.

    This function never raises. It is called as a spawn initializer, where an
    escaping exception aborts the child while the parent is still blocked in
    ``reader.recv()`` waiting for an address that will now never arrive.
    """
    if sys.platform == "win32":
        # Windows has no reparenting and no AF_UNIX listener directory, so
        # there is neither a signal to watch for nor a leak to clean up.
        return None
    try:
        original_ppid = _getppid()
        watcher = threading.Thread(
            target=_watch_for_reparenting,
            args=(original_ppid, poll_interval, _getppid, _on_orphan),
            name="memdiver-parent-death-watchdog",
            # Daemon, or this thread would hold a NORMAL interpreter shutdown
            # open for up to one poll interval on every well-behaved exit.
            daemon=True,
        )
        watcher.start()
        return watcher
    except Exception:
        logger.debug("parent-death watchdog not installed", exc_info=True)
        return None


def guard_child_process() -> None:
    """Spawn-initializer entry point: arm the watchdog in this child.

    Must stay module-level: ``spawn`` pickles the initializer by reference, so
    a nested function or a lambda would fail to resolve in the child, which
    surfaces as the parent hanging in ``reader.recv()`` rather than as a
    readable error.

    No try/except here - :func:`install_parent_death_watchdog` is total by
    construction and absorbs its own failures.
    """
    install_parent_death_watchdog()


def start_guarded_sync_manager(ctx) -> SyncManager:
    """``ctx.Manager()`` with a parent-death watchdog armed in the child.

    Inlines what :meth:`multiprocessing.context.BaseContext.Manager` does, so
    that ``initializer=`` can be passed to ``start()``. ``BaseManager.__init__``
    accepts ``ctx=``, so the caller's start method (spawn) is honoured exactly
    as ``ctx.Manager()`` honours it.
    """
    manager = SyncManager(ctx=ctx)
    manager.start(initializer=guard_child_process)
    return manager
