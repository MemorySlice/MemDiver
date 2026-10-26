"""Importable targets for ``tests/test_killable.py`` (run in a spawned child).

Spawn re-imports the target by dotted path, so these live in an importable module
(``tests`` is a package; the underscore keeps pytest from collecting this file).
"""

from __future__ import annotations

import os
import time

from memdiver.core.service_errors import CapabilityError, ErrorCategory


def add(a, b):
    return a + b


def big_dict(n):
    return {f"sym_{i}": i for i in range(n)}


def with_progress(steps, progress=None):
    for i in range(steps):
        progress({"stage": f"s{i}", "elapsed_s": float(i)})
    return steps


def raises_capability():
    raise CapabilityError("bad thing", category=ErrorCategory.NOT_FOUND, code="my.code",
                          details={"k": [1, 2], "path": os.path.sep})


def raises_generic():
    raise ValueError("boom")


def crash(code=3):
    os._exit(code)


def sleeps(seconds=60):
    time.sleep(seconds)


def pid():
    return os.getpid()


def sleeps_and_reports_pid(path):
    with open(path, "w") as handle:
        handle.write(str(os.getpid()))
    time.sleep(60)
