"""Persistence and validation for the API's ``oracle_dir``.

``oracle_dir`` is the directory user-supplied decryption oracles are stored in
and later *executed* from. It is therefore the highest-consequence path setting
in the API: enabling it is a consent decision ("MemDiver may run Python I give
it"), not a convenience default. It stays ``None`` — and every write endpoint
stays 503 — until the user explicitly opts in.

Historically the only way to opt in was ``MEMDIVER_ORACLE_DIR``, read exactly
once at startup, with no UI affordance and no default. This module is the
funnel that makes the same choice reachable at runtime, the way
:mod:`memdiver.api.upload_dir` already does for uploads:

* :func:`read_user_oracle_dir` / :func:`write_user_oracle_dir` persist the
  choice in the user-local, git-untracked ``memdiver_home()/config.json`` via
  the shared read-modify-write in :mod:`memdiver.api.user_prefs`.
* :func:`validate_candidate` vets a chosen path. It delegates the general
  rules to :func:`memdiver.api.upload_dir.validate_candidate` rather than
  restating them — a second copy of "which directories are unsafe" would be
  free to drift — and adds the one rule oracles need on top.

Nothing here imports :mod:`memdiver.api.config`, so ``config`` may import this
module during settings validation without a cycle.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from memdiver.api.upload_dir import validate_candidate as _validate_general
from memdiver.api.user_prefs import read_pref, user_config_path, write_pref

logger = logging.getLogger("memdiver.api.oracle_dir")

#: Key under which the chosen directory is stored in the user prefs file.
USER_CONFIG_KEY = "oracle_dir"


def default_oracle_dir() -> Path:
    """Return the directory offered when the user enables oracles without a path.

    Under ``memdiver_home()`` for the same reason the task root is
    (``api/config.py:_default_task_root``): it is per-user, already private,
    and survives a ``cd`` of the server process — unlike anything relative.
    """
    from memdiver.core.constants import memdiver_home

    return memdiver_home() / "oracles"


# ---------------------------------------------------------------------------
# User-config persistence
# ---------------------------------------------------------------------------


def read_user_oracle_dir() -> Path | None:
    """Return the oracle dir persisted in the user prefs file, else ``None``.

    Tolerant by design, mirroring
    :func:`memdiver.api.upload_dir.read_user_upload_dir`: a corrupt or
    unreadable prefs file must degrade to "not enabled" — which fails closed,
    since disabled is the safe state here — rather than break every request.
    """
    raw = read_pref(USER_CONFIG_KEY)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return Path(raw)


def write_user_oracle_dir(path: Path) -> None:
    """Persist *path* into the user prefs file, atomically and non-destructively.

    The atomicity and the read-modify-write both live in
    :func:`memdiver.api.user_prefs.write_pref`; the same file carries the
    upload dir, the wizard's ``skip_duckdb_setup`` flag and the file browser's
    favourites, so this write must not clobber them.
    """
    write_pref(USER_CONFIG_KEY, str(path))
    logger.info("Persisted oracle_dir=%s to %s", path, user_config_path())


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_candidate(raw: str) -> Path:
    """Return *raw* as a vetted, ready-to-use oracle directory.

    Two layers, deliberately:

    1. :func:`memdiver.api.upload_dir.validate_candidate` supplies every rule
       both directories share — absolute path, no system location, no
       world-writable temp root, not inside ``sys.prefix``, not bare ``$HOME``
       — and it *proves* writability by creating and writing the directory
       rather than trusting ``os.access``.
    2. The oracle-specific rule this adds: the directory is pinned to ``0o700``
       and the result is re-``stat``-ed to confirm no group/other write bit
       survived. ``engine.oracle._assert_safe_path`` refuses to load an oracle
       whose *parent directory* is group/world-writable, so a directory that
       fails this check would be accepted here and then reject every oracle
       stored in it at load time — a failure the user could only diagnose from
       a stack trace much later.

    Raises ``ValueError`` with a specific reason for each rejected class, the
    same convention :mod:`memdiver.api.upload_dir` uses.
    """
    resolved = _validate_general(raw, "oracle directory")

    # upload_dir.validate_candidate already calls ensure_ready() (mkdir +
    # chmod 0o700), so this is normally a no-op. It is repeated anyway because
    # the guarantee, not the call site, is what this function promises: an
    # inherited-permissions surprise here is a load-time refusal later.
    try:
        os.chmod(resolved, 0o700)
    except OSError as exc:
        raise ValueError(
            f"cannot set owner-only permissions on {resolved}: "
            f"{exc.strerror or exc}"
        ) from exc

    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise ValueError(
            f"cannot inspect {resolved}: {exc.strerror or exc}"
        ) from exc

    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(
            f"{resolved} stays group/world-writable (mode="
            f"{stat.filemode(mode)}) even after chmod 0o700; oracles cannot be "
            "loaded from a directory other local users can write to — choose a "
            "location on a filesystem that honours POSIX permissions"
        )

    return resolved
