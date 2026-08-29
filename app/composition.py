"""Single composition root: the one place object graphs are constructed.

Lives in ``app/`` and imports DOWN into ``app/``, ``engine/`` and ``core/``
only — never UP into a surface (``cli/``, ``api/``, ``mcp_server/``,
``run.py``). Those surfaces import FROM here instead of wiring dependencies
by hand, so there is exactly one place that knows how to build a
:class:`~memdiver.app.session.ToolSession`, a
:class:`~memdiver.core.discovery.DatasetScanner`, an
:class:`~memdiver.engine.pipeline.AnalysisPipeline`, or resolve the optional
:class:`~memdiver.engine.project_db.ProjectDB`.

Two conventions the repo relies on are preserved here verbatim:

* **Function-local (lazy) imports** inside every builder. This matches the
  repo-wide convention and keeps the module import-cheap while avoiding
  circular imports (surfaces import this module eagerly).
* **A single dump-open / key-material import surface** re-exported at module
  level. These are downward-only re-exports of the canonical openers; they are
  NOT reimplemented or collapsed. The caching invariant they encode
  (unkeyed → LRU cache; keyed → uncached) is load-bearing and untouched here.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import cost
    from pathlib import Path

    from memdiver.app.session import ToolSession
    from memdiver.core.discovery import DatasetScanner
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.project_db import ProjectDB

logger = logging.getLogger("memdiver.app.composition")


# ── Single dump-open / key-material import surface (re-exports) ───────
# Downward-only re-exports of the canonical openers. Do NOT reimplement or
# collapse these; the keyed→uncached / unkeyed→LRU-cache invariant is
# load-bearing and lives in the modules below, not here.
from memdiver.app.key_material import (
    has_key_material,
    key_material_kwargs,
    open_dump_source,
    open_msl_reader,
)
from memdiver.app.reader_cache import (
    cached_dump_source,
    cached_msl_reader,
    key_material_scope,
)
from memdiver.core.dump_source import open_dump  # UNCACHED primitive
from memdiver.core.key_material import (
    from_files as key_material_from_files,
    from_hex as key_material_from_hex,
)


# ── The one locked-container guard (shared by every opener's caller) ───
#
# Promoted here from three private copies (``app.tools_pipeline._raise_if_locked``,
# the inline block in ``app.export_service.auto_export_pattern``, and a third
# copy in ``api.routers.architect._read_static_regions``). It sits beside the
# openers above because it is the check every caller of those openers owes its
# user, and it is PUBLIC on purpose: a router reaching for another module's
# private name is worse than the duplication it replaces.


def raise_if_locked(source: object) -> None:
    """Raise :class:`EncryptedDumpLockedError` for an encrypted-and-locked source.

    A locked source (``tag_status`` MISSING_KEY / CORRUPTED) reads back EMPTY
    rather than raising. Without this guard every downstream empty/negative
    handler misattributes the lock: "no KEY_CANDIDATE regions", "every byte is
    invariant", "the key is absent from all N dumps". Each of those is a
    confident claim about bytes nobody ever decrypted.

    A decrypted source — including a genuinely empty one — and any
    non-encrypted source pass through untouched, so the existing empty-result
    error paths are preserved exactly.
    """
    from memdiver.core.service_errors import EncryptedDumpLockedError
    from memdiver.core.service_result import KeyStatus

    key = KeyStatus.from_source(source)
    if not key.decrypted:
        raise EncryptedDumpLockedError(key.hint)


# ── Builders (function-local imports; downward-only) ──────────────────

def build_tool_session() -> "ToolSession":
    """Return a fresh, stateful :class:`ToolSession`.

    Each call constructs a new instance; callers own its lifetime.
    """
    from memdiver.app.session import ToolSession

    return ToolSession()


def build_dataset_scanner(
    root: "Path",
    keylog_filename: str = "keylog.csv",
) -> "DatasetScanner":
    """Return a :class:`DatasetScanner` rooted at ``root``."""
    from memdiver.core.discovery import DatasetScanner

    return DatasetScanner(root, keylog_filename)


def resolve_project_db(db_path: "Optional[Path]" = None) -> "Optional[ProjectDB]":
    """Return an opened :class:`ProjectDB`, or ``None`` when unavailable.

    The optional DuckDB/Ibis backend degrades gracefully: if the dependency
    probe is not ready — or anything at all goes wrong while opening — this
    returns ``None`` rather than raising. The broad guard is intentional (a
    missing extra or a locked DB file must never propagate); the only change
    from the historical bare ``pass`` is a debug log for observability.
    """
    try:
        from memdiver.engine.project_db import (
            ProjectDB,
            check_deps,
            default_db_path,
        )

        if check_deps().get("ready"):
            db = ProjectDB(db_path or default_db_path())
            db.open()
            return db
    except Exception:
        logger.debug(
            "ProjectDB unavailable; continuing without persistence", exc_info=True
        )
    return None


def build_analysis_pipeline(
    *,
    project_db=None,
    auto_persist: "Optional[bool]" = None,
) -> "AnalysisPipeline":
    """Return an :class:`AnalysisPipeline` wired with the given persistence knobs.

    ``project_db`` and ``auto_persist`` are independent; they are AND-combined
    only at persistence time inside the pipeline. When ``auto_persist`` is left
    as ``None`` it defaults to ``True``, mirroring the constructor default
    exactly, and both values are passed straight through.
    """
    from memdiver.engine.pipeline import AnalysisPipeline

    if auto_persist is None:
        auto_persist = True
    return AnalysisPipeline(project_db=project_db, auto_persist=auto_persist)


__all__ = [
    # builders
    "build_tool_session",
    "build_dataset_scanner",
    "resolve_project_db",
    "build_analysis_pipeline",
    # core-layer openers
    "open_dump",
    "key_material_from_files",
    "key_material_from_hex",
    # the shared locked-container guard
    "raise_if_locked",
    # app-layer cached openers
    "cached_dump_source",
    "cached_msl_reader",
    "key_material_scope",
    # app-layer explicit-key-material openers
    "open_dump_source",
    "open_msl_reader",
    "key_material_kwargs",
    "has_key_material",
]
