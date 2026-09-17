"""Runnable victim process for ``test_orphaned_manager_self_terminates``.

Started as ``python -m tests._orphan_child``. It stands in for a MemDiver
server that is about to be SIGKILLed: it brings up one guarded SyncManager,
reports the facts the test needs to check afterwards, and then blocks forever
so the test controls exactly when it dies.

The single JSON line on stdout is the handshake. It must be flushed before the
sleep, or the test would kill a process whose pipe buffer still holds the only
record of which manager pid and which ``pymp-*`` directory to look for.

The underscore prefix keeps pytest from collecting this file as a test module,
matching ``tests/_task_runners.py``.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
import time

from memdiver.core.process_guard import start_guarded_sync_manager


def main() -> None:
    manager = start_guarded_sync_manager(mp.get_context("spawn"))
    # ``manager.address`` is the AF_UNIX listener socket the child minted
    # inside its own pymp directory, so its dirname IS the directory whose
    # removal proves the orphan ran its finalizers.
    handshake = {
        "manager_pid": manager._process.pid,
        "tempdir": os.path.dirname(manager.address),
    }
    sys.stdout.write(json.dumps(handshake) + "\n")
    sys.stdout.flush()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
