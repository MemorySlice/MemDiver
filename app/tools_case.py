"""Case data-lake producers: init, status, schema, query, context-at.

The ``case.*`` capabilities. Thin, surface-agnostic wrappers over
:class:`memdiver.analysis.case.Case` and
:func:`memdiver.analysis.context.locate_context`; each returns a
:class:`~memdiver.core.service_result.ServiceResult` with a plain-JSON payload
and RAISES a :class:`CapabilityError` on bad input. Locations are dicts as
produced by ``Location.to_dict()``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from memdiver.core.location import Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory, require_file
from memdiver.core.service_result import ServiceResult

if TYPE_CHECKING:  # DuckDB/Arrow load lazily: ``import memdiver`` reaches this module
    from memdiver.analysis.case import Case

#: Default layer cap of :func:`context_at_result` (``analysis.context.DEFAULT_LIMIT``).
DEFAULT_CONTEXT_LIMIT = 200

#: Default row cap of :func:`case_query_result`.
DEFAULT_QUERY_LIMIT = 1000


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _open(case_dir: str) -> "Case":
    from memdiver.analysis.case import Case

    if not case_dir or not str(case_dir).strip():
        raise _invalid("case_dir is required", "case_dir_required")
    return Case.open(Path(case_dir).expanduser())


def _case_info(case: "Case") -> Dict[str, Any]:
    return {"dir": str(case.dir), "name": case.name, "manifest": case.manifest()}


def case_init_result(case: str) -> "ServiceResult":
    """Create (or re-open) a case; a bare name means ``~/.memdiver/cases/<name>``."""
    if not case or not str(case).strip():
        raise _invalid("case is required", "case_required")
    from memdiver.analysis.case import Case

    return ServiceResult.ok(_case_info(Case.init(case)))


def case_status_result(case_dir: str) -> "ServiceResult":
    """Manifest, tables (runs and rows) and annotation captures of a case."""
    case = _open(case_dir)
    tables: Dict[str, Any] = {}
    for name in case.tables():
        runs = [ref.to_dict() for ref in case.runs(name)]
        tables[name] = {"runs": runs, "run_count": len(runs),
                        "rows": sum(r["row_count"] for r in runs)}
    from memdiver.analysis.record_store import AnalysisRecord

    record = AnalysisRecord(case.dir)
    captures = {cap: len(record.latest(cap)) for cap in record.captures()}
    return ServiceResult.ok({**_case_info(case), "tables": tables,
                             "annotation_captures": captures})


def case_schema_result(case_dir: str) -> "ServiceResult":
    """Per-table columns, location mappings, runs and rows, plus the annotations view."""
    return ServiceResult.ok(_open(case_dir).schema())


def case_query_result(case_dir: str, sql: str, limit: int = DEFAULT_QUERY_LIMIT,
                      params: Optional[Sequence[Any]] = None) -> "ServiceResult":
    """Run one read-only SELECT over the case tables; rows capped at ``limit``."""
    if not sql or not str(sql).strip():
        raise _invalid("sql is required", "sql_required")
    if limit < 1:
        raise _invalid("limit must be >= 1", "invalid_limit")
    result = _open(case_dir).query(sql, limit=limit, params=params)
    return ServiceResult.ok({**result.to_dict(), "row_count": result.table.num_rows,
                             "limit": limit, "elapsed_s": result.elapsed_s})


def _parse_location(location: Dict[str, Any]) -> Location:
    try:
        return Location.from_dict(dict(location))
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid(f"invalid location: {exc!r}", "invalid_location") from exc


def context_at_result(case_dir: str, location: Dict[str, Any], length: int = 1,
                      dump_path: Optional[str] = None,
                      tables: Optional[Sequence[str]] = None,
                      limit: int = DEFAULT_CONTEXT_LIMIT) -> "ServiceResult":
    """What contains ``location``: table rows and annotations, outermost first.

    With ``dump_path`` the dump is opened and, when its source supports
    ``read_location``, the stack also carries read coverage of
    ``[value, value + length)``.
    """
    from memdiver.analysis.context import locate_context

    case, loc = _open(case_dir), _parse_location(location)
    if length < 1:
        raise _invalid("length must be >= 1", "invalid_length")
    if not dump_path:
        return ServiceResult.ok(locate_context(case, loc, length=length, tables=tables,
                                               limit=limit).to_dict())
    from memdiver.core.dump_source import open_dump
    # open_dump returns the source UNOPENED: enter it, or read_location raises.
    with open_dump(Path(dump_path).expanduser()) as source:
        stack = locate_context(case, loc, source=source, length=length,
                               tables=tables, limit=limit)
    return ServiceResult.ok(stack.to_dict())


# -- case.export ------------------------------------------------------------------

#: Explicit ``what`` values of :func:`case_export_result`, with the dump formats
#: (``DumpSource.format_name``) each exporter applies to.
EXPORT_APPLIES_TO: Dict[str, tuple] = {
    "view_regions": ("image_view",),
    "msl_regions": ("msl",),
    "page_states": ("msl",),
    "heap_chunks": ("msl", "image_view"),
}

#: What ``"auto"`` expands to per format, in export order.
_AUTO_EXPORTS: Dict[str, tuple] = {
    "image_view": ("view_regions",),
    "msl": ("msl_regions", "page_states", "heap_chunks"),
}

_NO_HEAP_REASON = "no heap allocator detected"


def _resolve_exports(what: Sequence[str], format_name: str) -> List[str]:
    """Expand ``auto`` and reject an exporter the dump's format cannot feed."""
    wanted: List[str] = []
    for item in (what or ("auto",)):
        names = _AUTO_EXPORTS.get(format_name) if item == "auto" else (item,)
        if names is None:
            raise _invalid(f"nothing to export from a {format_name!r} dump "
                           "(expected an .mdview image view or an .msl)",
                           "export_not_applicable")
        wanted.extend(n for n in names if n not in wanted)
    for name in wanted:
        if name not in EXPORT_APPLIES_TO:
            raise _invalid(f"unknown export {name!r}; expected auto or one of: "
                           + ", ".join(EXPORT_APPLIES_TO), "unknown_export")
        if format_name not in EXPORT_APPLIES_TO[name]:
            raise _invalid(f"export {name!r} does not apply to a {format_name!r} dump",
                           "export_not_applicable")
    return wanted


def _heap_detected(dump_path: str) -> bool:
    from memdiver.heap.analyze import analyze_heap
    from memdiver.heap.model import AllocatorKind

    layout = analyze_heap(Path(dump_path))
    return layout.allocator != AllocatorKind.UNKNOWN and bool(layout.chunks)


def _run_export(case: "Case", name: str, dump_path: str, source: Any,
                run_id: Optional[str]):
    from memdiver.analysis import exporters

    if name == "view_regions":
        return exporters.export_view_regions(case, source, run_id=run_id)
    if name == "msl_regions":
        return exporters.export_msl_regions(case, dump_path, run_id=run_id)
    if name == "page_states":
        return exporters.export_page_state_runs(case, dump_path, run_id=run_id)
    return exporters.export_heap_chunks(case, dump_path, run_id=run_id)


def _export_row(ref: Any) -> Dict[str, Any]:
    return {"table": ref.name, "run_id": ref.run_id, "rows": ref.row_count,
            "path": ref.path}


def _companions(case: "Case", ref: Any) -> List[Dict[str, Any]]:
    """``proc_maps`` rides along with ``view_runs`` of a process view (same run)."""
    if ref.name != "view_runs" or "proc_maps" not in case.tables():
        return []
    return [_export_row(r) for r in case.runs("proc_maps") if r.run_id == ref.run_id]


def case_export_result(case_dir: str, dump_path: str,
                       what: Sequence[str] = ("auto",),
                       run_id: Optional[str] = None) -> "ServiceResult":
    """Export a dump's regions / page states / heap chunks into case tables.

    ``what`` is ``auto`` (everything applicable to the dump's format; heap is
    skipped when no allocator is detected) or any of :data:`EXPORT_APPLIES_TO`.
    Returns ``{"exports": [{table, run_id, rows, path}], "skipped": [{what, reason}]}``.
    """
    from memdiver.core.dump_source import open_dump

    case = _open(case_dir)
    path = require_file(dump_path, param="dump_path", label="dump", code="dump_not_found")
    exports: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    # open_dump returns the source UNOPENED: enter it, or the exporters raise.
    with open_dump(path) as source:
        wanted = _resolve_exports(what, source.format_name)
        auto_heap = "auto" in (what or ("auto",))
        for name in wanted:
            if name == "heap_chunks" and auto_heap and not _heap_detected(str(path)):
                skipped.append({"what": name, "reason": _NO_HEAP_REASON})
                continue
            try:
                ref = _run_export(case, name, str(path), source, run_id)
            except CapabilityError as exc:
                if name != "heap_chunks":
                    raise
                skipped.append({"what": name, "reason": exc.message})
                continue
            exports.append(_export_row(ref))
            exports.extend(_companions(case, ref))
    return ServiceResult.ok({"case_dir": str(case.dir), "dump_path": str(path),
                             "exports": exports, "skipped": skipped})


__all__ = ["DEFAULT_QUERY_LIMIT", "MANIFEST_LIST_CAP", "case_manifest_result", "EXPORT_APPLIES_TO", "case_init_result",
           "case_status_result", "case_schema_result", "case_query_result",
           "context_at_result", "case_export_result"]


# -- case manifest: the inventory (status is the summary) ------------------------

#: Per-list cap of :func:`case_manifest_result`; a clipped list sets ``truncated``.
MANIFEST_LIST_CAP = 500
_MANIFEST_SKIP_DIRS = frozenset({"tables", "annotations", "isf_drafts", "plugins", "isf"})


def _file_entry(case_dir: Path, path: Path) -> Dict[str, Any]:
    return {"path": str(path.relative_to(case_dir)), "size": path.stat().st_size}


def _capped(items: List[Any], truncated: Dict[str, bool], key: str) -> List[Any]:
    if len(items) > MANIFEST_LIST_CAP:
        truncated[key] = True
    return items[:MANIFEST_LIST_CAP]


def _manifest_views(case_dir: Path, warnings: List[str]) -> List[Dict[str, Any]]:
    from memdiver.core.image.view_descriptor import SUFFIX, ViewDescriptor

    out: List[Dict[str, Any]] = []
    for path in sorted((case_dir / "views").glob(f"*{SUFFIX}")):
        try:
            desc = ViewDescriptor.read(path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            warnings.append(f"unreadable view {path.name}: {exc}")
            out.append({"path": f"views/{path.name}", "kind": None, "image": None,
                        "pid": None, "error": str(exc)})
            continue
        out.append({"path": f"views/{path.name}", "kind": desc.view.value,
                    "image": str(desc.image_path(path)), "image_sha256": desc.image_sha256,
                    "pid": desc.pid})
    return out


def _image_stat(image: str, roots: List[Path],
                warnings: Optional[List[str]]) -> Dict[str, Any]:
    """``exists``/``size`` of an image; sandbox ON: never stat outside the read roots."""
    from memdiver.core import path_sandbox

    if roots and not path_sandbox.within(Path(image).expanduser().resolve(strict=False), roots):
        if warnings is not None:
            warnings.append(f"image {image!r} is outside the sandbox: not stat-ed")
        return {"exists": None, "size": None}
    try:
        size: Optional[int] = Path(image).stat().st_size
    except OSError:
        size = None
    return {"exists": size is not None, "size": size}


def _manifest_images(views: List[Dict[str, Any]], roots: Optional[List[Path]] = None,
                     warnings: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Distinct images the views refer to; ``stat`` only, never opened."""
    images: Dict[str, Dict[str, Any]] = {}
    for view in views:
        image = view.get("image")
        if not image or image in images:
            continue
        images[image] = {"path": image, **_image_stat(image, roots or [], warnings),
                         "views": 0}
    for view in views:
        if view.get("image") in images:
            images[view["image"]]["views"] += 1
    return list(images.values())


def _manifest_captures(case_dir: Path) -> List[Dict[str, Any]]:
    """Extracted ``.msl`` files anywhere in the case outside the managed subdirs."""
    found: List[Path] = []
    for path in sorted(case_dir.rglob("*.msl")):
        if path.is_file() and path.relative_to(case_dir).parts[0] not in _MANIFEST_SKIP_DIRS:
            found.append(path)
    return [_file_entry(case_dir, p) for p in found]


def _manifest_annotations_and_drafts(case_dir: Path, warnings: List[str]):
    from memdiver.analysis.record import ISF_DRAFT
    from memdiver.analysis.record_store import AnalysisRecord

    record = AnalysisRecord(case_dir)
    annotations: List[Dict[str, Any]] = []
    drafts: List[Dict[str, Any]] = []
    for cap in record.captures():
        try:
            annotations.append({"capture": cap, "entries": len(record.latest(cap))})
            ops: Dict[str, Dict[str, Any]] = {}
            for entry in record.entries(cap, kind=ISF_DRAFT):
                name = str(entry.payload.get("draft"))
                item = ops.setdefault(name, {"capture": cap, "name": name, "ops": 0})
                item["ops"] += 1
                if entry.payload.get("op") == "create":
                    item["arch"] = entry.payload.get("arch")
            drafts.extend(ops.values())
        except Exception as exc:  # noqa: BLE001 - inventory must survive one bad record
            warnings.append(f"unreadable annotations {cap}: {exc}")
    return annotations, drafts


def _manifest_isf_exports(case_dir: Path) -> List[Dict[str, Any]]:
    from memdiver.isf.draft import BLOBS_DIR, DRAFTS_DIR, ISF_SUFFIX

    paths = sorted(p for root in ("isf", DRAFTS_DIR) for p in (case_dir / root).rglob(f"*{ISF_SUFFIX}")
                   if p.is_file() and BLOBS_DIR not in p.relative_to(case_dir).parts)
    return [_file_entry(case_dir, p) for p in paths]


def _manifest_tables(case: "Case", warnings: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for name in case.tables():
        try:
            runs = case.runs(name)
            out.append({"name": name, "runs": len(runs),
                        "rows": sum(r.row_count for r in runs)})
        except (OSError, ValueError, KeyError) as exc:
            warnings.append(f"unreadable table {name}: {exc}")
            out.append({"name": name, "runs": None, "rows": None})
    return out


def case_manifest_result(case_dir: str,
                         read_roots: Optional[Sequence[Path]] = None) -> "ServiceResult":
    """Read-only inventory of a case: views, images, captures, annotations, ISF, plugins.

    Complements :func:`case_status_result` (a summary): this lists what files the
    case holds. Images are stat-ed, never opened; each list is capped at
    :data:`MANIFEST_LIST_CAP` with ``truncated[<list>]`` set when clipped.
    *read_roots* = the sandboxed surface's admitted read roots (REST/MCP pass them;
    empty/None = policy off): image paths outside them are never stat-ed.
    """
    case = _open(case_dir)
    root, warnings = case.dir, []  # type: Path, List[str]
    truncated: Dict[str, bool] = {}
    meta = case.manifest()
    views = _manifest_views(root, warnings)
    annotations, drafts = _manifest_annotations_and_drafts(root, warnings)
    plugins = [_file_entry(root, p) for p in sorted((root / "plugins").rglob("*")) if p.is_file()]
    body = {
        "case_dir": str(root), "name": case.name, "created": meta.get("created"),
        "version": meta.get("v"), "views": views,
        "images": _manifest_images(views, list(read_roots or []), warnings),
        "captures": _manifest_captures(root), "annotations": annotations,
        "isf": {"drafts": drafts, "exports": _manifest_isf_exports(root)},
        "plugins": plugins, "tables": _manifest_tables(case, warnings),
    }
    counts = {"views": len(views), "images": len(body["images"]),
              "captures": len(body["captures"]), "annotation_captures": len(annotations),
              "isf_drafts": len(drafts), "isf_exports": len(body["isf"]["exports"]),
              "plugins": len(plugins), "tables": len(body["tables"])}
    for key in ("views", "images", "captures", "annotations", "plugins", "tables"):
        body[key] = _capped(body[key], truncated, key)
    for key in ("drafts", "exports"):
        body["isf"][key] = _capped(body["isf"][key], truncated, f"isf.{key}")
    return ServiceResult.ok({**body, "record_counts": counts, "truncated": truncated,
                             "warnings": warnings})
