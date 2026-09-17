"""Shared ``pymp-*`` temp-dir assertions for the shutdown/teardown tests.

Every ``multiprocessing.Manager`` server owns a ``pymp-<random>`` directory
holding its unix socket, removed only by that child's own atexit finalizer. A
killed or orphaned Manager therefore leaves one behind -- 147 of them had
accumulated on the dev machine from ``kill -9``'d runs, which is the litter the
shutdown fix exists to stop.

Leakage is asserted as a set DIFFERENCE, never an absolute count. On macOS
``gettempdir()`` is the shared per-user ``/var/folders/<hash>/T``, so a ``== 0``
check would fail whenever ANY other Python process on the machine happens to
have a live Manager.

Removal is also asynchronous with respect to ``manager.shutdown()`` returning
(the child unlinks its own directory as it exits), so the assertion polls to a
deadline instead of reading once.

Underscore-prefixed like ``tests/_task_runners.py`` and ``tests/_paths.py``:
a shared helper module, not a collected test module.
"""

from __future__ import annotations

import os
import tempfile
import time
from glob import glob

# One deadline and one poll interval for every call site. These used to be
# copy-pasted per file and had already drifted to 5.0/10.0/10.0/20.0 seconds
# with three different clocks -- the shape that flakes one test on a loaded CI
# box while its three twins pass.
PYMP_SETTLE_TIMEOUT_S = 15.0
PYMP_POLL_S = 0.1


def pymp_dirs() -> set[str]:
    """Live ``pymp-*`` temp dirs -- one per multiprocessing Manager server."""
    return set(glob(os.path.join(tempfile.gettempdir(), "pymp-*")))


def assert_no_new_pymp_dirs(
    before: set[str], timeout: float = PYMP_SETTLE_TIMEOUT_S
) -> None:
    """Poll until no ``pymp-*`` dir exists that was absent in ``before``."""
    deadline = time.monotonic() + timeout
    leaked = pymp_dirs() - before
    while leaked and time.monotonic() < deadline:
        time.sleep(PYMP_POLL_S)
        leaked = pymp_dirs() - before
    assert not leaked, f"leaked Manager temp dirs: {sorted(leaked)}"
