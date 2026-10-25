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
    ``captured``.
    """
    from memdiver.app.session import ToolSession
    from memdiver.app.tools_inspect import vas_regions_result

    result = vas_regions_result(ToolSession(), str(msl_path))
    entries = result.payload["vas_entries"]
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
