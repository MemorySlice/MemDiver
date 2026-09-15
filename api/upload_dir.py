"""Persistence, validation and legacy migration for the API's ``upload_dir``.

``upload_dir`` is the directory uploaded packet captures and memory dumps land
in *and* the containment root every write-path check in the API measures
against (``api/path_safety.ensure_within``). It used to default to a hardcoded
``/tmp/memdiver_uploads`` — world-writable, predictable, and shared with every
other local user. It is now **configure-on-first-use**: unconfigured is a valid
state that fails *closed* (HTTP 409, see ``api.dependencies.upload_dir_or_409``)
and the user chooses the location the first time they upload.

This module is the single funnel for that choice:

* :func:`read_user_upload_dir` / :func:`write_user_upload_dir` persist it in the
  user-local, git-untracked ``memdiver_home()/config.json``, through the shared
  read-modify-write in :mod:`memdiver.api.user_prefs` — the file carries other
  features' settings too, so no write here may clobber them.
* :func:`validate_candidate` rejects a chosen path that would reintroduce the
  problem (temp dirs), damage the system, or hijack imports.
* :func:`legacy_dir_report` / :func:`migrate_legacy` offer a one-time move of
  files already sitting in the old ``/tmp`` directory.

Nothing here imports :mod:`memdiver.api.config`, so ``config`` may import this
module during settings validation without a cycle.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

from memdiver.api.user_prefs import read_pref, read_prefs, user_config_path, write_pref

logger = logging.getLogger("memdiver.api.upload_dir")

#: Key under which the chosen directory is stored in the user prefs file.
USER_CONFIG_KEY = "upload_dir"

#: Directories a chosen upload dir may never be, contain, or live inside.
#: Writing here either breaks the OS or needs privileges the tool must not use.
_SYSTEM_DIRS = (
    "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot", "/dev",
    "/proc", "/sys", "/System", "/Library", "/Applications",
)


def legacy_dir() -> Path:
    """Return the pre-B0 hardcoded upload directory, for migration only.

    Historical value: this path is read (to offer a migration) and, once
    emptied, removed. It is never written to and never becomes the active
    upload dir. ``nosec B108`` because flagging the very literal this change
    exists to eliminate would be backwards — keeping the constant here, behind
    one function, is what lets the rest of the codebase be free of it.
    """
    return Path("/tmp/memdiver_uploads")  # nosec B108


def _temp_roots() -> tuple[Path, ...]:
    """Return the resolved temp-directory roots a chosen dir may not live in.

    A function rather than a constant so tests can substitute roots: the
    pytest ``tmp_path`` fixture itself lives under ``tempfile.gettempdir()``,
    so a happy-path test could not otherwise name a directory validation
    accepts.
    """
    roots = [tempfile.gettempdir(), "/tmp", "/var/tmp"]  # nosec B108
    return tuple(dict.fromkeys(Path(r).resolve() for r in roots))


# ---------------------------------------------------------------------------
# User-config persistence
# ---------------------------------------------------------------------------


#: Kept as this module's own name for the prefs reader. The primitives moved to
#: :mod:`memdiver.api.user_prefs` when the file browser's favourites became a
#: second setting in the same file; the alias keeps every existing caller and
#: test that reaches for ``upload_dir._read_prefs`` working unchanged.
_read_prefs = read_prefs


def read_user_upload_dir() -> Path | None:
    """Return the upload dir persisted in the user prefs file, else ``None``.

    Tolerant by design: a corrupt or unreadable prefs file must degrade to
    "unconfigured" (which fails closed) rather than break every request.
    """
    raw = read_pref(USER_CONFIG_KEY)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return Path(raw)


def write_user_upload_dir(path: Path) -> None:
    """Persist *path* into the user prefs file, atomically and non-destructively.

    The atomicity and the read-modify-write both live in
    :func:`memdiver.api.user_prefs.write_pref` — the prefs file also carries the
    setup wizard's ``skip_duckdb_setup`` flag and the file browser's favourite
    directories, so the other keys must survive this write.
    """
    write_pref(USER_CONFIG_KEY, str(path))
    logger.info("Persisted upload_dir=%s to %s", path, user_config_path())


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

#: Default noun for refusal messages. Overridable so a sibling setting can
#: reuse these rules without misnaming what the user chose.
_DEFAULT_LABEL = "upload directory"


def _reject_system_locations(resolved: Path, label: str = _DEFAULT_LABEL) -> None:
    """Raise ``ValueError`` if *resolved* is, contains, or sits in a system dir.

    ``label`` names the thing being chosen, so a caller validating something
    other than an upload directory (see :mod:`memdiver.api.oracle_dir`) gets a
    refusal that describes what the user was actually picking.
    """
    if resolved == Path(resolved.anchor):
        raise ValueError(f"the filesystem root is not a valid {label}")
    for raw in _SYSTEM_DIRS:
        for d in {Path(raw), Path(raw).resolve()}:
            if resolved == d or d in resolved.parents:
                raise ValueError(
                    f"{resolved} is inside the system directory {d} — "
                    "choose a location in your own files"
                )
            if resolved in d.parents:
                raise ValueError(
                    f"{resolved} contains the system directory {d} — "
                    "choose a more specific location"
                )


def validate_candidate(raw: str, label: str = _DEFAULT_LABEL) -> Path:
    """Return *raw* as a vetted, ready-to-use upload directory.

    ``label`` only changes the wording of the refusals, never which paths are
    refused; it exists so a sibling setting can reuse these rules verbatim
    without telling the user their oracle directory is a bad "upload
    directory".

    Raises ``ValueError`` with a specific reason for each rejected class. The
    candidate is ``expanduser()``-ed then ``resolve()``-d before every check, so
    a symlink aimed at ``/etc`` is caught structurally — the same posture as
    :func:`api.path_safety.ensure_within`.
    """
    if not raw or not raw.strip():
        raise ValueError("no path given")
    raw = raw.strip()
    if not raw.startswith(("/", "~")):
        raise ValueError(f"{raw!r} is not an absolute path")

    resolved = Path(raw).expanduser().resolve()

    _reject_system_locations(resolved, label)

    for root in _temp_roots():
        if resolved == root or root in resolved.parents:
            raise ValueError(
                f"{resolved} is inside the temporary directory {root}; "
                "temp directories are world-writable and cleared on reboot — "
                "choose a persistent, private location"
            )

    prefix = Path(sys.prefix).resolve()
    if resolved == prefix or prefix in resolved.parents:
        raise ValueError(
            f"{resolved} is inside the Python installation at {prefix}; "
            "writing there could hijack module imports"
        )

    home = Path.home().resolve()
    if resolved == home:
        raise ValueError(
            f"your home directory itself is not a valid {label} — "
            "choose a subdirectory of it"
        )

    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"{resolved} exists and is not a directory")

    # Writability is PROVEN, never inferred: os.access(W_OK) lies under POSIX
    # ACLs, read-only mounts and macOS SIP.
    try:
        ensure_ready(resolved)
        with tempfile.NamedTemporaryFile(dir=resolved, delete=True):
            pass
    except OSError as exc:
        raise ValueError(
            f"cannot write to {resolved}: {exc.strerror or exc}"
        ) from exc

    return resolved


def ensure_ready(path: Path) -> Path:
    """Create *path* if needed and pin it to owner-only 0o700, then return it.

    The chmod is unconditional (not just on creation): the directory holds
    uploaded packet captures and memory dumps, which must not be readable by
    other local users even if the chosen directory already existed.
    """
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    # mkdir()'s mode is masked by the process umask and ignored entirely when
    # the directory already exists; chmod makes 0o700 a guarantee.
    os.chmod(path, 0o700)
    return path


# ---------------------------------------------------------------------------
# Legacy /tmp migration
# ---------------------------------------------------------------------------


def legacy_dir_report() -> dict | None:
    """Summarise the legacy ``/tmp`` upload dir, or ``None`` if none to offer.

    Returns ``None`` when the directory is absent, empty, not a directory, or
    is itself a symlink (a planted link is never something to offer moving).
    """
    legacy = legacy_dir()
    try:
        if os.path.islink(legacy):
            logger.warning("legacy upload dir %s is a symlink; ignoring", legacy)
            return None
        if not legacy.is_dir():
            return None
        entries = list(os.scandir(legacy))
    except OSError as exc:
        logger.warning("cannot inspect legacy upload dir %s: %s", legacy, exc)
        return None
    if not entries:
        return None

    total = 0
    count = 0
    for entry in entries:
        count += 1
        try:
            total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            continue
    try:
        owned = os.lstat(legacy).st_uid == os.getuid()
    except OSError:
        owned = False
    return {
        "path": str(legacy),
        "file_count": count,
        "total_bytes": total,
        "owned_by_us": owned,
    }


def migrate_legacy(dest: Path) -> tuple[int, int]:
    """Move the legacy ``/tmp`` upload dir's contents into *dest*.

    Returns ``(migrated, skipped)``. The legacy directory lives in a
    ``drwxrwxrwt`` world-writable location, so another local user can plant
    entries in it. The rules below are what keep a "migration" from becoming
    an attack primitive:

    * refuse entirely if the legacy directory is a symlink, or is not owned by
      us (someone else created it and controls its contents);
    * **skip any entry that is itself a symlink** — otherwise migrating would
      relocate an attacker's link into the user's new private directory, where
      subsequent reads would follow it back out;
    * skip name collisions rather than clobber the user's own files;
    * per-entry failures are logged and counted as ``skipped``, never fatal;
    * the legacy directory is removed only if it ends up genuinely empty.
    """
    legacy = legacy_dir()
    if os.path.islink(legacy):
        logger.warning("refusing to migrate: %s is a symlink", legacy)
        return (0, 0)
    try:
        if os.lstat(legacy).st_uid != os.getuid():
            logger.warning("refusing to migrate: %s is not owned by us", legacy)
            return (0, 0)
        entries = list(os.scandir(legacy))
    except OSError as exc:
        logger.warning("refusing to migrate %s: %s", legacy, exc)
        return (0, 0)

    ensure_ready(dest)
    migrated = 0
    skipped = 0
    for entry in entries:
        src = Path(entry.path)
        if entry.is_symlink():
            logger.warning("skipping symlink %s during migration", src)
            skipped += 1
            continue
        target = dest / src.name
        if target.exists():
            logger.warning("skipping %s: %s already exists", src, target)
            skipped += 1
            continue
        try:
            shutil.move(str(src), str(target))
        except (OSError, shutil.Error) as exc:
            logger.warning("failed to migrate %s: %s", src, exc)
            skipped += 1
            continue
        migrated += 1

    try:
        legacy.rmdir()
        logger.info("removed emptied legacy upload dir %s", legacy)
    except OSError:
        # Not empty (skipped entries) or not removable — both fine.
        pass
    return (migrated, skipped)
