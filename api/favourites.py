"""Favourite directories for the file browser, and the last place it was.

The browse dialog opens on ``Path.home()`` every single time (see
``api/routers/path.py``), which makes returning to a working directory a walk
down the tree on every visit. Favourites are the fix, and they are kept HERE —
server side, in ``memdiver_home()/config.json`` — rather than in the browser's
``localStorage``, because that store is keyed by origin: running
``memdiver web`` on a different ``--port``, clearing site data, or opening the
UI in another browser would each silently produce an empty list. A forensic
workspace's directories outlive all three.

This module owns the feature end to end — the stored shape, validation and the
upsert rules — so ``api/routers/settings.py`` stays a thin HTTP surface, the
same split ``api/upload_dir.py`` already has with that router.

Validation here is deliberately WEAKER than
:func:`memdiver.api.upload_dir.validate_candidate`. That one vets a *write*
target: it mkdirs, chmods 0o700, proves writability with a real temp file, and
rejects temp roots and ``sys.prefix``. A favourite is only ever read from and
navigated to, so demanding any of that would reject perfectly good bookmarks —
a read-only directory, or one inside a temp tree, is a legitimate thing to
save.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from memdiver.api.user_prefs import read_pref, write_pref

logger = logging.getLogger("memdiver.api.favourites")

#: Prefs key holding the list of favourite directories.
FAVOURITES_KEY = "favourite_dirs"

#: Prefs key holding the directory the browser should reopen on.
LAST_DIR_KEY = "last_browsed_dir"

#: Upper bound on the list. Not a product limit anyone will meet by hand — it
#: is there because this list shares a file with unrelated settings, and a
#: looping client must not be able to grow that file without end.
MAX_FAVOURITES = 100


def default_label(path: Path) -> str:
    """Return the label a favourite gets when the user supplies none.

    The directory's own name, which is what a person recognises in a list.
    Resolved to ``/`` at the filesystem root, where there is no name.
    """
    return path.name or "/"


def validate_favourite(raw: str) -> Path:
    """Return *raw* as a vetted favourite directory, or raise ``ValueError``.

    Absolute, existing and a directory. Nothing more: see the module docstring
    for why the upload-dir checks do not apply to a path we only ever read.
    """
    if not raw or not raw.strip():
        raise ValueError("no path given")
    raw = raw.strip()
    if not raw.startswith(("/", "~")):
        raise ValueError(f"{raw!r} is not an absolute path")

    resolved = Path(raw).expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"{resolved} does not exist")
    if not resolved.is_dir():
        raise ValueError(f"{resolved} is not a directory")
    return resolved


def _clean(entry: object) -> dict | None:
    """Return *entry* as a well-formed favourite, or ``None`` to drop it.

    The prefs file is user-editable and shared, so a malformed entry is a thing
    to survive rather than a thing to raise on: one bad line must not cost the
    user the rest of their list.
    """
    if not isinstance(entry, dict):
        return None
    path = entry.get("path")
    if not isinstance(path, str) or not path.strip():
        return None
    label = entry.get("label")
    added_at = entry.get("added_at")
    return {
        "path": path,
        "label": label if isinstance(label, str) and label.strip() else default_label(Path(path)),
        "added_at": added_at if isinstance(added_at, (int, float)) else 0,
    }


def read_favourites() -> list[dict]:
    """Return the stored favourites, dropping anything malformed."""
    raw = read_pref(FAVOURITES_KEY, [])
    if not isinstance(raw, list):
        return []
    return [cleaned for cleaned in (_clean(entry) for entry in raw) if cleaned]


def add_favourite(raw_path: str, label: str | None = None) -> list[dict]:
    """Add *raw_path*, or relabel it if already saved. Returns the new list.

    An upsert rather than an add because the path IS the identity: saving the
    same directory twice is the user asking for one entry, not two, and it is
    also how a rename is expressed without a second endpoint.
    """
    resolved = validate_favourite(raw_path)
    stored = str(resolved)
    chosen = label.strip() if label and label.strip() else default_label(resolved)

    favourites = read_favourites()
    for entry in favourites:
        if entry["path"] == stored:
            # Keep `added_at`: relabelling is not re-adding.
            entry["label"] = chosen
            break
    else:
        if len(favourites) >= MAX_FAVOURITES:
            raise ValueError(
                f"cannot save more than {MAX_FAVOURITES} favourites; "
                "remove one before adding another"
            )
        favourites.append(
            {"path": stored, "label": chosen, "added_at": int(time.time())}
        )

    write_pref(FAVOURITES_KEY, favourites)
    return favourites


def remove_favourite(raw_path: str) -> list[dict]:
    """Drop *raw_path* from the list. Returns the new list.

    Matched on the path as GIVEN and on its resolved form, so an entry whose
    directory has since been deleted — which ``validate_favourite`` would
    refuse — can still be removed. A favourite you cannot delete because its
    target is gone is the worst possible version of this feature.
    """
    candidates = {raw_path.strip()}
    try:
        candidates.add(str(Path(raw_path).expanduser().resolve()))
    except (OSError, RuntimeError):  # pragma: no cover - defensive
        pass

    favourites = [e for e in read_favourites() if e["path"] not in candidates]
    write_pref(FAVOURITES_KEY, favourites)
    return favourites


def read_last_dir() -> str | None:
    """Return the directory the browser should reopen on, if one is known."""
    raw = read_pref(LAST_DIR_KEY)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw


def write_last_dir(raw_path: str) -> str:
    """Remember *raw_path* as where the browser was last used.

    Validated the same way a favourite is, so a bad value can never make the
    next browse open on something that is not a directory.
    """
    resolved = validate_favourite(raw_path)
    write_pref(LAST_DIR_KEY, str(resolved))
    return str(resolved)
