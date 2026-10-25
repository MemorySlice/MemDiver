"""Pure tool functions for MemDiver — dataset discovery and analysis.

Each function takes a ToolSession + explicit params and returns a dict.
The MCP server and future web gateway both call these directly.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Union

from memdiver.core.discovery import RunDiscovery
from memdiver.core.input_schemas import AnalyzeRequest
from memdiver.core.protocols import REGISTRY
from memdiver.core.service_errors import (CapabilityError, ErrorCategory,
                                         FileNotFoundServiceError)
from memdiver.engine.batch import run_analysis_request
from memdiver.engine.serializer import serialize_result

from .session import ToolSession

if TYPE_CHECKING:  # pragma: no cover - typing only
    from memdiver.msl.region_select import RegionSelection

logger = logging.getLogger("memdiver.app.tools")


def scan_dataset(
    session: ToolSession,
    root: str,
    keylog_filename: str = "keylog.csv",
    protocols: Optional[List[str]] = None,
) -> dict:
    """Scan a dataset directory for available protocols, libraries, and phases.

    The payload is :func:`engine.serializer.serialize_dataset_info` applied to
    the :class:`core.discovery.DatasetInfo` produced by the scan, so it also
    carries the packet-capture inventory: ``runs_with_capture`` (how many runs
    own a capture) and ``captures`` (per ``"ver/scenario/library"`` counts).
    Both ride the existing return dict — no new producer, no new capability.

    ``session.set_dataset`` raises :class:`FileNotFoundServiceError` for a
    missing root; that propagates to the caller's transport funnel.
    """
    session.set_dataset(root)
    return session.get_or_scan(keylog_filename, protocols)


def list_phases(session: ToolSession, library_dir: str) -> dict:
    """List available lifecycle phases for a library directory."""
    path = Path(library_dir)
    if not path.is_dir():
        raise FileNotFoundServiceError(f"Directory not found: {library_dir}")

    runs = RunDiscovery.discover_library_runs(path)
    if not runs:
        return {"library_dir": library_dir, "phases": [], "runs": 0}

    phases = sorted({p for run in runs for p in run.available_phases()})
    return {
        "library_dir": library_dir,
        "library": runs[0].library,
        "phases": phases,
        "runs": len(runs),
    }


def list_protocols(session: ToolSession) -> dict:
    """List all registered protocol descriptors."""
    result = []
    for name in REGISTRY.list_protocols():
        desc = REGISTRY.get(name)
        if desc is None:
            continue
        result.append({
            "name": desc.name,
            "versions": desc.versions,
            "secret_types": {v: sorted(types) for v, types in desc.secret_types.items()},
            "dir_prefix": desc.dir_prefix,
        })
    return {"protocols": result}


def _region_filter_state(session: ToolSession) -> dict:
    """The session's region view filter as ``{"region_filter", "active"}``."""
    return {
        "region_filter": session.region_filter,
        "active": session.region_filter is not None,
    }


def set_region_filter(session: ToolSession,
                      region_filter: Optional[str] = None) -> dict:
    """Set (or clear) the session's analysis-time region view filter.

    ``region_filter`` is a category list (``"heap,stack"``), a persisted note
    (``"regions=..."``) or ``"all"``/``None``/``""``, which clear it. Tools that
    take ``region_filter`` fall back to this value when the caller omits theirs.
    Returns the normalised ``to_note()`` form. An unknown category name raises
    an INVALID_INPUT :class:`CapabilityError` and leaves the filter unchanged.
    """
    try:
        session.set_region_filter(region_filter)
    except ValueError as exc:
        raise CapabilityError(f"Invalid region filter: {exc}") from exc
    return _region_filter_state(session)


def get_region_filter(session: ToolSession) -> dict:
    """Return the session's region view filter (``None`` = every region)."""
    return _region_filter_state(session)


def analyze_library(
    session: ToolSession,
    library_dirs: List[str],
    phase: str,
    protocol_version: str,
    keylog_filename: str = "keylog.csv",
    template_name: str = "Auto-detect",
    max_runs: int = 10,
    normalize: bool = False,
    expand_keys: bool = True,
    algorithms: Optional[List[str]] = None,
    *,
    force: bool = False,
) -> dict:
    """Run the full analysis pipeline on library directories.

    ``force`` bypasses the consensus memory-budget guard.
    """
    lib_paths = [Path(d) for d in library_dirs]
    for p in lib_paths:
        if not p.is_dir():
            raise FileNotFoundServiceError(f"Directory not found: {p}")

    try:
        request = AnalyzeRequest(
            library_dirs=lib_paths,
            phase=phase,
            protocol_version=protocol_version,
            keylog_filename=keylog_filename,
            template_name=template_name,
            max_runs=max_runs,
            normalize=normalize,
            expand_keys=expand_keys,
            algorithms=algorithms,
            force=force,
        )
    except ValueError as exc:
        raise CapabilityError(str(exc))

    result = run_analysis_request(request)
    return serialize_result(result)


SelectionSpec = Union[str, "RegionSelection", None]


def _coerce_selection(selection: SelectionSpec,
                      exclude: Optional[str] = None):
    """``"heap,stack"`` / ``"all"`` / RegionSelection / None -> selection.

    ``None`` (and no *exclude*) keeps the import-everything default. A bad
    spec raises an INVALID_INPUT :class:`CapabilityError`.
    """
    from memdiver.msl.region_select import RegionSelection, parse_selection

    if isinstance(selection, RegionSelection):
        if exclude is None:
            return selection
        selection = ",".join(c.value for c in selection.categories)
    try:
        return parse_selection(selection, exclude)
    except ValueError as exc:
        raise CapabilityError(str(exc)) from None


def _require_maps_file(maps_path: Optional[str]) -> Optional[Path]:
    """*maps_path* as a Path (``None`` when unset); missing -> not found."""
    if not maps_path:
        return None
    maps = Path(maps_path)
    if not maps.is_file():
        raise FileNotFoundServiceError(f"Maps file not found: {maps_path}")
    return maps


def import_dump(
    session: ToolSession,
    raw_path: str,
    output_path: str,
    pid: int = 0,
    selection: SelectionSpec = None,
    materialize: bool = False,
    exclude: Optional[str] = None,
    key_material: Optional[dict] = None,
    decrypt_output: bool = False,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    maps_path: Optional[str] = None,
) -> dict:
    """Import a dump (raw .dump, ELF core, or minidump) to .msl format.

    Delegates to :func:`msl.importer.import_dump`, which sniffs the source
    format and dispatches to the raw, ELF-core, or minidump importer. Plain
    raw .dump imports remain a byte-for-byte no-op regression.

    *selection* restricts the import to some region categories: a
    :class:`~memdiver.msl.region_select.RegionSelection` or a spec string
    such as ``"heap,stack"`` / ``"all"``; *exclude* (e.g. ``"image"``) drops
    categories. ``None`` for both imports everything. For ``.msl`` input
    the copy stays verbatim unless *materialize* is True. Selection outcome
    fields (``selection``, ``excluded_region_count``, ``excluded_bytes``,
    ``secrets_only_in_excluded``, ``warnings``) appear only when relevant.

    *key_material* (``core.key_material`` dict, request-scoped, never cached or
    logged) opens an encrypted ``.msl``; a materialized copy is re-encrypted
    under the same key wrapping unless *decrypt_output* asks for plaintext.
    *key_file* / *passphrase* / *kem_key_file* (file-path idiom, MCP) are an
    alternative to *key_material*. A missing or wrong key on a materialize
    raises ``CapabilityError`` (``PRECONDITION``) and writes nothing.

    *maps_path* names a ``/proc/<pid>/maps``-style memory map that splits a
    raw dump into real regions (default: auto-detect a ``.maps`` sidecar
    next to the dump). Formats with their own layout ignore it (warning).
    """
    key_material = _import_key_material(key_material, key_file, passphrase,
                                        kem_key_file)
    src = Path(raw_path)
    if not src.is_file():
        raise FileNotFoundServiceError(f"File not found: {raw_path}")
    maps = _require_maps_file(maps_path)
    region_selection = _coerce_selection(selection, exclude)

    from memdiver.msl.importer import import_dump as _import

    try:
        result = _import(src, Path(output_path), pid=pid,
                         selection=region_selection, materialize=materialize,
                         key_material=key_material,
                         decrypt_output=decrypt_output,
                         **({"maps_path": maps} if maps else {}))
    except ValueError as exc:
        if not _is_key_error(exc):
            raise
        raise CapabilityError(str(exc), category=ErrorCategory.PRECONDITION
                              ) from None
    response = {
        "source": str(result.source_path),
        "output": str(result.output_path),
        "regions_written": result.regions_written,
        "key_hints_written": result.key_hints_written,
        "total_bytes": result.total_bytes,
    }
    if result.has_selection_info:  # shape unchanged when nothing selected
        response.update(result.selection_summary())
    return response


def preview_import(
    session: ToolSession,
    path: str,
    selection: SelectionSpec = None,
    exclude: Optional[str] = None,
    key_material: Optional[dict] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    maps_path: Optional[str] = None,
) -> dict:
    """Metadata-only preview of the regions an import of *path* would emit.

    Returns :meth:`ImportPreview.to_dict` — ``format``, ``is_msl``, per-region
    ``regions`` (with ``category``), per-category ``totals`` and a
    ``summary`` of what *selection* / *exclude* would keep and drop. Reads no
    region payloads and writes nothing. Key material (dict or the file-path
    params) opens an encrypted ``.msl`` so its regions are listed; the result
    carries ``encrypted`` / ``decrypted``. ``layout`` says where the regions
    came from (``native`` / ``maps`` / ``none``); *maps_path* is the memory
    map of a raw dump, as for :func:`import_dump`.
    """
    key_material = _import_key_material(key_material, key_file, passphrase,
                                        kem_key_file)
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundServiceError(f"File not found: {path}")
    maps = _require_maps_file(maps_path)
    region_selection = _coerce_selection(selection, exclude)

    from memdiver.app.image_preview import is_image_view_path

    if is_image_view_path(src):
        return _preview_image_view(src, region_selection)

    from memdiver.msl.import_preview import preview_import as _preview

    try:
        preview = _preview(src, key_material=key_material, maps_path=maps)
    except ValueError as exc:
        raise CapabilityError(f"cannot preview {path}: {exc}") from None
    return preview.to_dict(region_selection)


def _preview_image_view(src: Path, selection: Optional["RegionSelection"]) -> dict:
    """:func:`preview_import` of an ``.mdview`` (VMAs, not file bytes)."""
    from memdiver.app.image_preview import image_view_preview

    return image_view_preview(src, selection)


def import_raw_dump(
    session: ToolSession,
    raw_path: str,
    output_path: str,
    pid: int = 0,
    selection: SelectionSpec = None,
    materialize: bool = False,
    exclude: Optional[str] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    decrypt_output: bool = False,
    maps_path: Optional[str] = None,
) -> dict:
    """Back-compat alias for :func:`import_dump`.

    Retained so existing callers keep working; new code should call
    :func:`import_dump`, which routes through the unified dispatcher.
    """
    return import_dump(session, raw_path, output_path, pid=pid,
                       selection=selection, materialize=materialize,
                       exclude=exclude, key_file=key_file,
                       passphrase=passphrase, kem_key_file=kem_key_file,
                       decrypt_output=decrypt_output, maps_path=maps_path)


def _import_key_material(key_material: Optional[dict], key_file: Optional[str],
                         passphrase: Optional[str],
                         kem_key_file: Optional[str]) -> Optional[dict]:
    """Explicit dict wins; else decode the file-path params (``None`` if none).

    Request-scoped (``app/reader_cache.py`` rule): never cached or logged.
    """
    if key_material is not None:
        return key_material
    if not (key_file or passphrase or kem_key_file):
        return None
    from memdiver.core.key_material import from_files
    return from_files(key_file, passphrase, kem_key_file)


def _is_key_error(exc: ValueError) -> bool:
    """True for the importer's missing/wrong-key materialize refusals."""
    text = str(exc)
    return "key material required" in text or "decryption failed" in text
