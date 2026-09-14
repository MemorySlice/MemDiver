"""The user-local preferences file, and the durable write it needs.

``memdiver_home()/config.json`` is the *untracked*, per-user file the server
writes settings the user chose into. Deliberately NOT the repo-root
``config.json`` that ``Settings.config_path`` points at: that one is
git-tracked and read-only as far as the server is concerned.

Several unrelated settings share this one file — the upload directory
(``api/upload_dir.py``), the setup wizard's ``skip_duckdb_setup`` flag, and the
file browser's favourite directories — which is the whole reason this module
exists. Every write is a READ-MODIFY-WRITE through :func:`write_pref`, so one
setting can never silently erase another, and it lands via a sibling
``.json.tmp`` that is chmod'd ``0o600`` and then ``replace``-d into place, so a
crash mid-write cannot truncate the file and lose the other settings with it.

Reads are tolerant on purpose: a corrupt or unreadable prefs file degrades to
"nothing is configured" rather than breaking every request that touches it.

Nothing here imports :mod:`memdiver.api.config`, so ``config`` may import this
module during settings validation without a cycle.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("memdiver.api.user_prefs")


def user_config_path() -> Path:
    """Return the user-local prefs file every setting here is stored in."""
    from memdiver.core.constants import memdiver_home

    return memdiver_home() / "config.json"


def read_prefs() -> dict:
    """Return the parsed user prefs file, or ``{}`` when absent/unreadable."""
    path = user_config_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def read_pref(key: str, default: Any = None) -> Any:
    """Return the value stored under *key*, or *default* when it is absent."""
    return read_prefs().get(key, default)


def write_pref(key: str, value: Any) -> None:
    """Persist *value* under *key*, atomically and without touching the rest.

    See the module docstring for why both halves of that sentence matter: the
    other settings in this file belong to other features, and a truncated
    prefs file would take them all with it.
    """
    target = user_config_path()
    prefs = read_prefs()
    prefs[key] = value
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(prefs, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(target)
    logger.info("Persisted %s to %s", key, target)
