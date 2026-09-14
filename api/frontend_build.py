"""Where the built web UI lives, and whether it is older than the source.

``memdiver web`` serves the PREBUILT bundle in ``frontend/dist``; it does not
compile anything. Vite's dev server is a separate thing that only the frontend
test suite and ``npm run dev`` ever start. The consequence is a trap with no
symptom: edit ``frontend/src``, restart the server, and you are handed the
previous build — same URL, no error, no warning, nothing in the log. The change
simply is not there, and the natural conclusion is that the code is broken.

So the server says so. :func:`frontend_build_warning` is the one check, and it
is deliberately a plain function returning text rather than a log call, so the
caller decides where it goes and the whole thing is testable without capturing
log records.

Scope of the heuristic, stated honestly: it compares the newest mtime under
``frontend/src`` with the newest under ``frontend/dist``. It therefore misses a
change to ``frontend/index.html``, ``vite.config.ts`` or ``package.json``, and
it can report a false positive after a ``git checkout`` rewrites source mtimes.
Both are the right way round — a needless "you may want to rebuild" costs a
command, while a missed stale build costs an afternoon.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

#: Env override for the served bundle, matching the ``Settings`` env prefix.
#: Used by packaged or relocated deployments where the source-tree-relative
#: default does not apply.
DIST_ENV_VAR = "MEMDIVER_FRONTEND_DIST"

#: The command that rebuilds the bundle, quoted in every message below.
BUILD_COMMAND = "npm run build --workspace frontend"


def _package_root() -> Path:
    """The ``memdiver`` package root — ``frontend/`` sits beside the modules."""
    return Path(__file__).parent.parent


def frontend_dist_path() -> Path:
    """Return the directory the web UI is served from."""
    override = os.environ.get(DIST_ENV_VAR)
    if override:
        return Path(override)
    return _package_root() / "frontend" / "dist"


def frontend_src_path() -> Path:
    """Return the frontend source tree. Absent in a packaged install."""
    return _package_root() / "frontend" / "src"


def newest_file(root: Path) -> tuple[Path, float] | None:
    """Return the most recently modified file under *root*, or ``None``.

    ``None`` covers both "no such directory" and "no files in it" — neither is
    something to compare against, and neither is an error worth raising during
    startup.
    """
    newest: tuple[Path, float] | None = None
    for path in root.rglob("*"):
        try:
            if not path.is_file():
                continue
            mtime = path.stat().st_mtime
        except OSError:
            # A symlink to nowhere, or a file that vanished mid-walk. Skipping
            # it is right: this is advisory, and a broken entry says nothing
            # about whether the build is current.
            continue
        if newest is None or mtime > newest[1]:
            newest = (path, mtime)
    return newest


def _stamp(mtime: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))


def _display(path: Path) -> str:
    """Path relative to the package root when possible, else absolute."""
    try:
        return str(path.relative_to(_package_root()))
    except ValueError:
        return str(path)


def frontend_build_warning() -> str | None:
    """Return what the user needs to be told about the built UI, or ``None``.

    Silent in the two cases where there is nothing actionable to say: a
    packaged install with no source tree, and a bundle relocated by
    ``MEMDIVER_FRONTEND_DIST`` (an operator who set that knows where their
    build comes from, and this repo's ``frontend/src`` is not what produced it).
    """
    if os.environ.get(DIST_ENV_VAR):
        return None

    src = frontend_src_path()
    if not src.is_dir():
        return None

    dist = frontend_dist_path()
    if not dist.is_dir():
        return (
            f"WARNING: no built web UI found at {_display(dist)}.\n"
            "  The API is running, but the browser interface will not be served.\n"
            "\n"
            "  To build it:\n"
            f"    {BUILD_COMMAND}\n"
        )

    newest_src = newest_file(src)
    newest_dist = newest_file(dist)
    if newest_src is None or newest_dist is None:
        return None
    if newest_src[1] <= newest_dist[1]:
        return None

    return (
        "WARNING: the built web UI is OLDER than the frontend source.\n"
        "  You will be served the PREVIOUS build. Nothing on screen says so —\n"
        "  every change made since that build simply will not be there.\n"
        "\n"
        f"    newest source   {_stamp(newest_src[1])}  {_display(newest_src[0])}\n"
        f"    built UI        {_stamp(newest_dist[1])}  {_display(dist)}\n"
        "\n"
        "  To apply your changes:\n"
        f"    1. {BUILD_COMMAND}\n"
        "    2. reload the page with a hard refresh (Cmd/Ctrl+Shift+R) — the\n"
        "       browser caches index.html, so a plain reload can keep serving\n"
        "       the old bundle even after a rebuild.\n"
        "\n"
        "  Restarting this server is not required: the files are read per request.\n"
    )
