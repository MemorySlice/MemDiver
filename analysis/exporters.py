"""Library exporters: existing MemDiver producers -> case data-lake tables.

Each exporter reads one producer's output and registers ONE table through
:meth:`Case.register_table`, filling the standard columns (``pid``, ``space``,
``addr``, ``size``) and declaring ``addr``'s coordinate system in
``locations``. They return the :class:`TableRef`. Nothing here is a surface:
CLI/REST/MCP wiring calls these.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import pyarrow as pa

from memdiver.analysis.capture_id import capture_id_for
from memdiver.analysis.case import Case, TableRef
from memdiver.core.location import AddressSpace


def _standard(space: str, pid: Optional[int], addrs: List[int],
              sizes: List[int], **extra: Sequence[Any]) -> pa.Table:
    """Table with the standard columns plus ``extra`` columns."""
    rows = len(addrs)
    columns: Dict[str, Any] = {
        "pid": pa.array([pid] * rows, type=pa.int64()),
        "space": pa.array([space] * rows, type=pa.string()),
        "addr": pa.array(addrs, type=pa.uint64()),
        "size": pa.array(sizes, type=pa.uint64()),
    }
    columns.update({name: list(values) for name, values in extra.items()})
    return pa.table(columns)


def _register(case: Case, name: str, table: pa.Table, space: str, *,
              capture_id: str, image_sha256: Optional[str], run_id: Optional[str],
              producer: str) -> TableRef:
    return case.register_table(
        name, table, capture_id=capture_id, run_id=run_id,
        image_sha256=image_sha256, producer=f"memdiver.{producer}",
        locations={"addr": space})


# -- image views (.mdview) --------------------------------------------------


def export_view_regions(case: Case, source: Any, *,
                        run_id: Optional[str] = None) -> TableRef:
    """Table ``view_runs``: one row per run of an open ``Vol3LayerSource``.

    Returns the ``view_runs`` ref; a process view also gets ``proc_maps``
    (see :func:`export_process_vmas`), found with ``case.runs("proc_maps")``.

    Columns: standard + ``state`` (captured / failed / not_resident).
    ``space`` is the view's own address space; ``pid`` is set for process views.
    """
    descriptor = source.descriptor
    space = source.location(0).space.value
    runs = list(source.layer_runs())
    table = _standard(space, descriptor.pid, [r.start for r in runs],
                      [r.length for r in runs], state=[r.state.value for r in runs])
    ref = _register(case, "view_runs", table, space,
                    capture_id=descriptor.capture_id,
                    image_sha256=descriptor.image_sha256, run_id=run_id,
                    producer="export_view_regions")
    if source.vmas():  # process views also list their VMAs
        export_process_vmas(case, source, run_id=run_id)
    return ref


def export_process_vmas(case: Case, source: Any, *,
                        run_id: Optional[str] = None) -> TableRef:
    """Table ``proc_maps``: one row per VMA of a process view (``process_va``).

    Columns: standard + ``name``, ``protection``, ``is_heap``.
    """
    descriptor = source.descriptor
    vmas = source.vmas()
    table = _standard(AddressSpace.PROCESS_VA.value, descriptor.pid,
                      [v.start for v in vmas], [v.end - v.start for v in vmas],
                      name=[v.name for v in vmas],
                      protection=[v.protection for v in vmas],
                      is_heap=[bool(v.is_heap) for v in vmas])
    return _register(case, "proc_maps", table, AddressSpace.PROCESS_VA.value,
                     capture_id=descriptor.capture_id,
                     image_sha256=descriptor.image_sha256, run_id=run_id,
                     producer="export_process_vmas")


# -- .msl captures ----------------------------------------------------------


def _msl_pid(msl_path: str) -> Optional[int]:
    from memdiver.core.dump_source import open_dump

    with open_dump(Path(msl_path)) as source:
        return source.metadata().get("pid")


def export_msl_regions(case: Case, msl_path: str, *,
                       run_id: Optional[str] = None) -> TableRef:
    """Table ``msl_regions``: the VAS map of an ``.msl`` (space ``msl_va``).

    Columns: standard + ``region_type``, ``protection``, ``mapped_path``,
    ``captured``. A capture with no VAS map falls back to its captured region
    headers (``mapped_path`` null), so the table is never silently empty.
    """
    from memdiver.app.session import ToolSession
    from memdiver.app.tools_inspect import vas_regions_result

    result = vas_regions_result(ToolSession(), str(msl_path))
    entries = result.payload["vas_entries"] or _captured_region_entries(msl_path)
    space = AddressSpace.MSL_VA.value
    table = _standard(
        space, _msl_pid(msl_path), [e["base_addr"] for e in entries],
        [e["region_size"] for e in entries],
        region_type=[e["region_type"] for e in entries],
        protection=[e["protection"] for e in entries],
        mapped_path=[e.get("mapped_path") for e in entries],
        captured=[e.get("captured") for e in entries])
    return _register(case, "msl_regions", table, space,
                     capture_id=capture_id_for(msl_path), image_sha256=None,
                     run_id=run_id, producer="export_msl_regions")


def _captured_region_entries(msl_path: str) -> List[Dict[str, Any]]:
    """VAS-entry-shaped rows from the region headers of an ``.msl`` with no VAS map.

    Only the regions the capture actually holds; ``mapped_path`` is unknown.
    """
    from memdiver.msl.reader import MslReader

    with MslReader(Path(msl_path)) as reader:
        regions = reader.collect_regions()
    return [{"base_addr": r.base_addr, "region_size": r.region_size,
             "region_type": r.region_type, "protection": r.protection,
             "mapped_path": None, "captured": True} for r in regions]


def export_page_state_runs(case: Case, msl_path: str, *,
                           run_id: Optional[str] = None) -> TableRef:
    """Table ``msl_page_states``: non-CAPTURED VA runs of an ``.msl``.

    Columns: standard + ``state`` (FAILED / UNMAPPED / NOT_RESIDENT).
    CAPTURED runs are omitted, as in the page-state producer.
    """
    from memdiver.app.page_state_runs import cached_state_table
    from memdiver.msl.reader import MslReader

    with MslReader(Path(msl_path)) as reader:
        runs = list(cached_state_table(reader))
    space = AddressSpace.MSL_VA.value
    table = _standard(space, _msl_pid(msl_path), [r[0] for r in runs],
                      [r[1] - r[0] for r in runs], state=[r[2] for r in runs])
    return _register(case, "msl_page_states", table, space,
                     capture_id=capture_id_for(msl_path), image_sha256=None,
                     run_id=run_id, producer="export_page_state_runs")


# -- heap, YARA -------------------------------------------------------------


def export_heap_chunks(case: Case, dump_path: str, *, allocator: str = "auto",
                       base_va: Optional[int] = None,
                       run_id: Optional[str] = None) -> TableRef:
    """Table ``heap_chunks``: allocator chunks, addressed by their VA.

    ``HeapChunk.va`` is a virtual address, so ``space`` is ``msl_va`` for an
    ``.msl`` and ``process_va`` otherwise. Columns: standard + ``state``,
    ``user_addr``, ``user_len``, ``bin``, ``confidence``.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.heap.analyze import analyze_heap

    with open_dump(Path(dump_path)) as source:
        chunks = list(analyze_heap(source, allocator, base_va=base_va).chunks)
        pid = source.metadata().get("pid")
    space = _heap_space(dump_path)
    table = _standard(
        space, pid, [c.va for c in chunks], [c.size for c in chunks],
        state=[c.state.value for c in chunks],
        user_addr=[c.user_va for c in chunks],
        user_len=[c.user_len for c in chunks],
        bin=[c.bin for c in chunks], confidence=[c.confidence for c in chunks])
    return _register(case, "heap_chunks", table, space,
                     capture_id=capture_id_for(dump_path), image_sha256=None,
                     run_id=run_id, producer="export_heap_chunks")


def _heap_space(dump_path: str) -> str:
    is_msl = str(dump_path).lower().endswith(".msl")
    return (AddressSpace.MSL_VA if is_msl else AddressSpace.PROCESS_VA).value


def export_yara_matches(case: Case, matches: Iterable[Any], *, capture_id: str,
                        space: str, pid: Optional[int] = None,
                        image_sha256: Optional[str] = None,
                        run_id: Optional[str] = None) -> TableRef:
    """Table ``yara_hits``: ``RuleMatch`` objects (offset -> addr, length -> size).

    Columns: standard + ``rule``, ``string_id``, ``tags`` (comma-joined),
    ``key_offset``, ``key_length``. ``space`` names the matches' coordinates.
    """
    hits = list(matches)
    table = _standard(
        space, pid, [m.offset for m in hits], [m.length for m in hits],
        rule=[m.rule for m in hits], string_id=[m.string_id for m in hits],
        tags=[",".join(m.tags) for m in hits],
        key_offset=pa.array([m.key_offset for m in hits], type=pa.int64()),
        key_length=pa.array([m.key_length for m in hits], type=pa.int64()))
    return _register(case, "yara_hits", table, space, capture_id=capture_id,
                     image_sha256=image_sha256, run_id=run_id,
                     producer="export_yara_matches")


# -- key finders ------------------------------------------------------------

_KEY_HIT_UINT_COLUMNS = ("va", "vas_offset", "heap_chunk_va", "heap_chunk_size",
                         "region_start", "region_end")
_KEY_HIT_TEXT_COLUMNS = ("finder", "label", "key_hex", "heap_role", "heap_state",
                         "region_perms", "region_path", "metadata_json")


def export_key_hits(case: Case, hits: Sequence[Dict[str, Any]], *, capture_id: str,
                    space: str, pid: Optional[int] = None,
                    image_sha256: Optional[str] = None,
                    run_id: Optional[str] = None,
                    truncated: bool = False) -> TableRef:
    """Table ``key_hits``: one row per key-finder hit (``addr`` in ``space``).

    ``hits`` are flat dicts (the key-finder producer builds them): ``addr`` and
    ``length`` are required; ``length`` lands in the standard ``size`` column.
    Columns: standard + ``confidence`` (double), the text columns
    :data:`_KEY_HIT_TEXT_COLUMNS` and the nullable uint64 columns
    :data:`_KEY_HIT_UINT_COLUMNS`. ``va`` (the hit's virtual address, always
    ``msl_va`` / ``process_va``-style) is declared a location too when any row has
    one, so ``key_hits`` joins ``heap_chunks`` / ``msl_regions`` on ``va`` even when
    ``addr`` is a packed-stream offset. ``truncated`` is recorded on the run.
    """
    rows = list(hits)
    extra: Dict[str, Any] = {"confidence": pa.array(
        [r.get("confidence") for r in rows], type=pa.float64())}
    for name in _KEY_HIT_TEXT_COLUMNS:
        extra[name] = pa.array([r.get(name) for r in rows], type=pa.string())
    for name in _KEY_HIT_UINT_COLUMNS:
        extra[name] = pa.array([r.get(name) for r in rows], type=pa.uint64())
    table = _standard(space, pid, [r["addr"] for r in rows],
                      [r["length"] for r in rows], **extra)
    locations = {"addr": space}
    if any(r.get("va") is not None for r in rows):
        locations["va"] = (AddressSpace.MSL_VA.value if space in (
            AddressSpace.MSL_VA.value, AddressSpace.MSL_VAS.value) else space)
    return case.register_table(
        "key_hits", table, capture_id=capture_id, run_id=run_id,
        image_sha256=image_sha256, producer="memdiver.export_key_hits",
        locations=locations, meta={"truncated": bool(truncated)})


# -- strings ----------------------------------------------------------------

_STRING_UINT_COLUMNS = ("chars", "va", "vas_offset", "region_start", "region_end")
_STRING_TEXT_COLUMNS = ("encoding", "value", "region_perms", "region_path")


def export_strings(case: Case, rows: Sequence[Dict[str, Any]], *, capture_id: str,
                   space: str, pid: Optional[int] = None,
                   image_sha256: Optional[str] = None,
                   run_id: Optional[str] = None,
                   truncated: bool = False) -> TableRef:
    """Table ``strings``: one row per extracted string (``addr`` in ``space``).

    ``rows`` are flat dicts: ``addr`` and ``byte_length`` (the string's extent in
    the dump, stored in the standard ``size`` column) are required. Columns:
    standard + the text columns :data:`_STRING_TEXT_COLUMNS` and the nullable
    uint64 columns :data:`_STRING_UINT_COLUMNS`. ``va`` is declared a location
    too when any row has one, so ``strings`` joins ``heap_chunks`` /
    ``msl_regions`` on ``va`` even when ``addr`` is a packed-stream offset.
    ``truncated`` is recorded on the run (a saved query refuses a truncated table).
    """
    items = list(rows)
    extra: Dict[str, Any] = {}
    for name in _STRING_TEXT_COLUMNS:
        extra[name] = pa.array([r.get(name) for r in items], type=pa.string())
    for name in _STRING_UINT_COLUMNS:
        extra[name] = pa.array([r.get(name) for r in items], type=pa.uint64())
    table = _standard(space, pid, [r["addr"] for r in items],
                      [r["byte_length"] for r in items], **extra)
    locations = {"addr": space}
    if any(r.get("va") is not None for r in items):
        locations["va"] = (AddressSpace.MSL_VA.value if space in (
            AddressSpace.MSL_VA.value, AddressSpace.MSL_VAS.value) else space)
    return case.register_table(
        "strings", table, capture_id=capture_id, run_id=run_id,
        image_sha256=image_sha256, producer="memdiver.export_strings",
        locations=locations, meta={"truncated": bool(truncated)})


_DISASM_TEXT_COLUMNS = ("mnemonic", "op_str", "bytes_hex", "stop_reason")


def export_disasm(case: Case, rows: Sequence[Dict[str, Any]], *, capture_id: str,
                  space: str, pid: Optional[int] = None,
                  image_sha256: Optional[str] = None,
                  run_id: Optional[str] = None,
                  truncated: bool = False) -> TableRef:
    """Table ``disasm``: one row per decoded instruction (``addr`` in ``space``).

    ``rows`` are flat dicts: ``addr`` (int) and ``size`` are required; the text
    columns :data:`_DISASM_TEXT_COLUMNS` are optional. ``truncated`` is recorded
    on the run.
    """
    items = list(rows)
    extra = {name: pa.array([r.get(name) for r in items], type=pa.string())
             for name in _DISASM_TEXT_COLUMNS}
    table = _standard(space, pid, [r["addr"] for r in items],
                      [r["size"] for r in items], **extra)
    return case.register_table(
        "disasm", table, capture_id=capture_id, run_id=run_id,
        image_sha256=image_sha256, producer="memdiver.export_disasm",
        locations={"addr": space}, meta={"truncated": bool(truncated)})
