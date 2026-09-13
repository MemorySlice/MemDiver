"""In-app documentation router — serve the repo's ``docs/*.md`` to the SPA.

Why this exists
---------------
Four empty states in the SPA used to link at ``/docs/<path>.md``. Nothing has
ever served that path: ``api/main.py`` mounts only ``/notebook`` and the
``frontend/dist`` static catch-all, FastAPI's own Swagger UI owns the exact
path ``/docs``, and the Vite dev server's ``server.fs.allow`` deliberately
excludes the repo-root ``docs/`` tree. Every click returned ``Not Found``.

So the markdown is served from ``/api/docs/{doc_path}`` instead — a sibling of
every other ``/api/...`` router, which means it inherits the same token guard
(``api/security.py``'s ``_ALWAYS_EXEMPT_PATHS`` is exact-match only and does
NOT cover it, which is correct) and it is registered before the ``/``
StaticFiles mount so the SPA build still owns every other path.

Contract
--------
``GET /api/docs/{doc_path:path}`` -> ``{"path": str, "content": str}``

JSON rather than ``text/markdown`` so the frontend's one ``request<T>()``
helper in ``frontend/src/api/client.ts`` (which always parses JSON) can call it
unmodified, and so the 404 body can carry the published-docs fallback URL as a
structured field instead of prose the client has to scrape.

``docs/`` is shipped in the wheel (see ``MANIFEST.in`` /
``[tool.setuptools.package-data]``), but an install can still be missing it —
a source checkout pruned for size, a distro repackage. The 404 therefore names
:data:`PUBLISHED_DOCS_URL` so the panel can always offer a working link.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException

logger = logging.getLogger("memdiver.api.routers.docs")

router = APIRouter()

#: ``<package root>/docs``. This file is ``<package root>/api/routers/docs.py``,
#: so three ``.parent`` hops — one more than ``api/main.py``'s two, which
#: resolves the same directory from ``<package root>/api/main.py``.
DOCS_ROOT = Path(__file__).parent.parent.parent / "docs"

#: Where the same markdown is published as HTML. ``<path>.md`` maps to
#: ``<path>.html`` there.
PUBLISHED_DOCS_URL = "https://memoryslice.github.io/MemDiver/"

#: The only extension served. Not a whitelist of *safety* (the resolve-and-
#: contain check below is what makes traversal impossible) but of *intent*:
#: this endpoint publishes prose, never code, config or fixtures.
_ALLOWED_SUFFIX = ".md"


def _published_url_for(doc_path: str) -> str:
    """The published-docs URL a ``docs/``-relative ``.md`` path maps to."""
    if doc_path.endswith(_ALLOWED_SUFFIX):
        doc_path = doc_path[: -len(_ALLOWED_SUFFIX)] + ".html"
    return PUBLISHED_DOCS_URL + doc_path.lstrip("/")


def resolve_doc(doc_path: str, root: Path | None = None) -> Path:
    """Resolve ``doc_path`` inside ``root``, or raise ``HTTPException(400)``.

    Rejects, in order: an empty path, anything not ending in ``.md``, an
    absolute path, any ``..`` segment, an NT drive/UNC prefix, and — the
    load-bearing check — any resolved path that is not contained by the
    resolved root. The last one is what actually holds: it catches symlinks
    out of the tree and any encoding the four syntactic checks miss.
    """
    root = (root or DOCS_ROOT).resolve()

    if not doc_path or not doc_path.strip():
        raise HTTPException(status_code=400, detail="Empty documentation path.")
    if not doc_path.endswith(_ALLOWED_SUFFIX):
        raise HTTPException(
            status_code=400,
            detail=f"Only '{_ALLOWED_SUFFIX}' documentation files are served.",
        )

    candidate = Path(doc_path)
    if candidate.is_absolute() or candidate.drive or candidate.root:
        raise HTTPException(
            status_code=400, detail="Absolute documentation paths are not served."
        )
    if any(part == ".." for part in candidate.parts):
        raise HTTPException(
            status_code=400, detail="Relative traversal is not permitted."
        )

    resolved = (root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        logger.warning("rejected out-of-tree documentation path: %r", doc_path)
        raise HTTPException(
            status_code=400, detail="Documentation path escapes the docs root."
        )
    return resolved


@router.get("/{doc_path:path}")
def read_doc(doc_path: str):
    """Return one markdown document from the bundled ``docs/`` tree."""
    resolved = resolve_doc(doc_path)
    if not resolved.is_file():
        raise HTTPException(
            status_code=404,
            detail={
                "message": f"Documentation page not found: {doc_path}",
                "path": doc_path,
                "docs_url": _published_url_for(doc_path),
            },
        )
    try:
        content = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("failed to read documentation page %s: %s", resolved, exc)
        raise HTTPException(
            status_code=404,
            detail={
                "message": f"Documentation page is unreadable: {doc_path}",
                "path": doc_path,
                "docs_url": _published_url_for(doc_path),
            },
        ) from exc
    return {"path": doc_path, "content": content}
