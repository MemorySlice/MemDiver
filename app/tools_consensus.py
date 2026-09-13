"""Aligned-window producer — the ONE place N dumps are read in correspondence.

The problem this module exists to remove
----------------------------------------
A consensus vector puts N dumps into correspondence, but it expresses that
correspondence in a coordinate (the aligned *slab*) that no dump can be read
in. Every surface that wanted to show "the same bytes in all N dumps" therefore
had to do its own slab -> VA -> navigable-offset arithmetic, and both shipped
overlay bugs came from exactly that: one client applied a peer coordinate in
the wrong view, another assumed ONE relocation delta per dump when adjacent
aligned pages can carry different ones.

So the client never receives a peer coordinate it has to apply. It receives,
per dump, a byte string ALREADY in window coordinates:

**Invariant W1.** For every dump ``d`` and every ``i`` in ``[0, length)``,
``dumps[d].bytes[i]`` is the byte ``d`` holds at the address the consensus put
in correspondence with the anchor's byte at ``offset + i``; ``classes[i]`` is
that correspondence's ByteClass. Where no correspondence exists: ``i`` falls in
a ``gaps`` run, ``classes[i] == -1``, ``bytes[i] == 0x00``, and ``i`` is
outside every ``bytes_valid`` run.

``segments[].dumps[].va`` / ``.offset`` are PROVENANCE — where the bytes came
from, for an operator who wants to go look — never something to apply. They are
per SEGMENT per dump, not one scalar per dump: under ``module_offset``
alignment two adjacent slab pages can carry different relocation deltas, so a
single peer offset would be wrong in a way that reads as plausible bytes.

Why the peer bytes are re-read here
-----------------------------------
``engine.consensus_service.build_consensus`` closes its sources before it
returns, and ``api.services.consensus_session.ConsensusSession`` keeps only the
matrix — no sources, no key material. The peer bytes therefore CANNOT come from
the stored build; every selected dump is re-opened exactly once (one
``ExitStack``, so the anchor's own open is the same open its bytes are read
from) and read while it is live.

Why ``view`` is not the caller's choice per dump
------------------------------------------------
``MslDumpSource.va_to_file_offset`` deliberately answers with the *block
header's* file offset rather than the byte's, so a ``view="raw"`` peer read
lands on real bytes at the WRONG address — plausible-looking garbage, which is
the exact failure this endpoint exists to prevent. Each source is therefore
read in the view in which an offset names a BYTE for the coordinate in play
(:func:`_peer_view`): for an ALIGNED build that is ``"va"`` for ``.msl`` and
``"vas"`` for gcore / regioned raw; for a FLAT build it is the same flat stream
the build compared; for the no-consensus path it is the raw file, which is the
only thing that path ever claimed to compare.
"""

from __future__ import annotations

import base64
import logging
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)
from memdiver.engine.consensus import (
    MAX_CONSENSUS_WINDOW,
    AlignedSegment,
    ConsensusVector,
    WindowProjection,
    flat_alignment_report,
)

from .session import ToolSession

if TYPE_CHECKING:  # annotations only; the producer imports it in-body
    from memdiver.core.service_result import ServiceResult

logger = logging.getLogger("memdiver.app.tools_consensus")

#: Ceiling on ``length * n_dumps``. A window is N byte strings wide, so the
#: per-window cap alone does not bound the response: 32 dumps at 16 KiB is half
#: a megabyte of base64 per request. When this bites, ``length`` is CLAMPED and
#: ``truncated`` is set — a dump is NEVER dropped, because a silently missing
#: dump reads as "this dump has nothing there", a different and wrong answer.
MAX_WINDOW_TOTAL_BYTES = 262144

#: Ceiling on how many dumps one window may cover.
MAX_WINDOW_DUMPS = 32

#: Views in which an offset names a byte rather than a container structure.
NAVIGABLE_VIEWS = ("va", "vas", "raw")

#: Which coordinate the window's offsets live in.
#:
#: * ``"aligned"`` — the consensus slab; peers are addressed by virtual address.
#: * ``"flat"`` — a flat-offset (``file_offset``) build; the coordinate is the
#:   very byte stream ``ConsensusVector._build_raw`` compared.
#: * ``"raw_file"`` — no consensus at all; the coordinate is the raw file, which
#:   is what :func:`_unclassified_report` measured with ``stat``.
COORDINATE_ALIGNED = "aligned"
COORDINATE_FLAT = "flat"
COORDINATE_RAW_FILE = "raw_file"


# ---------------------------------------------------------------------------
# VA <-> navigable-offset: ONE helper, both directions
# ---------------------------------------------------------------------------


def _navigable_view(source: Any) -> str:
    """The view of ``source`` in which an offset names a BYTE by address.

    ``.msl`` -> ``"va"`` (``_read_range_va`` serves the sparse VA span
    directly); gcore / regioned raw -> ``"vas"`` (``va_to_vas_offset`` is
    byte-accurate over the flat VAS stream); anything else -> ``"raw"``, which
    for a flat dump is the only coordinate it has.

    NEVER ``"raw"`` for an ``.msl``: see the module docstring.
    """
    if getattr(source, "format_name", "") == "msl":
        return "va"
    if getattr(source, "supports_va_alignment", False):
        return "vas"
    return "raw"


def _peer_view(source: Any, coordinate: str) -> str:
    """The view a dump must be read in for the coordinate the window is in."""
    if coordinate == COORDINATE_RAW_FILE:
        return "raw"
    if coordinate == COORDINATE_FLAT:
        # `_build_raw` compared `source.read_all()`, i.e. each source's own
        # default stream: "vas" for `.msl`, "raw" for a flat dump.
        return "raw" if _navigable_view(source) == "raw" else "vas"
    return _navigable_view(source)


def _vas_runs(source: Any) -> Iterator[Tuple[int, int, int]]:
    """Yield ``(va_start, run_length, vas_offset)`` for every captured run.

    Normalizes the two ``iter_ranges`` shapes in the codebase: ``.msl`` yields
    ``(va, length, chunk)`` over a flat stream whose offsets are cumulative,
    while the regioned / gcore sources yield ``(start_va, end_va, file_offset)``
    where the VAS offset IS the file offset.
    """
    if getattr(source, "format_name", "") == "msl":
        flat = 0
        for va, run, _chunk in source.iter_ranges():
            yield (int(va), int(run), flat)
            flat += int(run)
        return
    for start_va, end_va, file_offset in source.iter_ranges():
        run = int(end_va) - int(start_va)
        if run > 0:
            yield (int(start_va), run, int(file_offset))


def _translate_va(
    source: Any,
    view: str,
    *,
    va: Optional[int] = None,
    offset: Optional[int] = None,
) -> Optional[int]:
    """Convert between an absolute VA and a navigable offset in ``view``.

    Exactly one of ``va`` / ``offset`` is given; the other is returned, or
    ``None`` when the address is not addressable in that view. BOTH directions
    live in this one function on purpose: the anchor conversion runs
    offset -> VA and every peer conversion runs VA -> offset, and a pair of
    separately-maintained functions is how the two stop agreeing.

    ``None`` rather than a plausible number: a wrong-but-plausible offset sends
    a viewer to real bytes that mean nothing.
    """
    if (va is None) == (offset is None):
        raise ValueError("_translate_va takes exactly one of va= / offset=")

    if view == "va":
        # Linear: the "va" view is the whole VA span, based at its start.
        span_start = _va_span_start(source)
        if span_start is None:
            return None
        if va is not None:
            out = int(va) - span_start
            return out if out >= 0 else None
        return span_start + int(offset or 0)

    if view == "vas":
        if va is not None:
            target_va = int(va)
            for run_va, run, vas_offset in _vas_runs(source):
                if run_va <= target_va < run_va + run:
                    return vas_offset + (target_va - run_va)
            return None
        target_off = int(offset or 0)
        for run_va, run, vas_offset in _vas_runs(source):
            if vas_offset <= target_off < vas_offset + run:
                return run_va + (target_off - vas_offset)
        return None

    if view == "raw":
        # A flat dump has no virtual addresses, and an `.msl`'s raw view is the
        # container — `va_to_file_offset` would answer with a block header, not
        # the byte. Refusing keeps that read unreachable by accident.
        return None

    raise ValueError(f"Unknown view: {view!r} (expected one of {NAVIGABLE_VIEWS})")


def _va_span_start(source: Any) -> Optional[int]:
    """Base VA of the ``"va"`` view, or ``None`` when the source has none."""
    metadata = getattr(source, "metadata", None)
    if metadata is None:
        return None
    start = metadata().get("va_span_start")
    return None if start is None else int(start)


# ---------------------------------------------------------------------------
# Dump selection + caps
# ---------------------------------------------------------------------------


def _select_dumps(
    consensus: Optional[ConsensusVector],
    dumps: Optional[Sequence[Any]],
) -> List[Tuple[int, str]]:
    """Resolve the ``dumps`` selector to ``[(dump_index, dump_path)]``.

    Accepts indices into the build order or dump paths — the two spellings a
    client naturally has. With no selector, every dump of the build. Without a
    consensus the selector IS the dump list, so its entries must be paths.
    """
    if consensus is None:
        paths = [str(d) for d in (dumps or [])]
        if not paths:
            raise CapabilityError("no dumps were named for an unclassified window")
        _check_subset_cap(len(paths))
        return list(enumerate(paths))

    all_paths = list(consensus.dump_paths)
    if not all_paths:
        raise CapabilityError(
            "this consensus recorded no dump paths, so its bytes cannot be "
            "re-read (an incremental/upload build folds bytes, not files)",
            category=ErrorCategory.PRECONDITION,
            status=409,
        )
    if dumps is None:
        _check_subset_cap(len(all_paths))
        return list(enumerate(all_paths))

    selected: List[Tuple[int, str]] = []
    for entry in dumps:
        index = _dump_index_for(consensus, entry)
        if index < 0:
            raise FileNotFoundServiceError(f"dump not part of this consensus: {entry}")
        selected.append((index, all_paths[index]))
    _check_subset_cap(len(selected))
    return selected


def _check_subset_cap(count: int) -> None:
    if count > MAX_WINDOW_DUMPS:
        raise CapabilityError(
            f"a window may cover at most {MAX_WINDOW_DUMPS} dumps, got {count}",
            details={"n_dumps": count, "max_dumps": MAX_WINDOW_DUMPS},
        )


def _dump_index_for(consensus: ConsensusVector, entry: Any) -> int:
    """Index of ``entry`` (an int index or a dump path) in the build order."""
    if isinstance(entry, bool):  # bool is an int; never a dump selector
        return -1
    if isinstance(entry, int):
        return entry if 0 <= entry < len(consensus.dump_paths) else -1
    return consensus.dump_index_for_path(str(entry))


def _clamp_length(requested: int, n_dumps: int) -> Tuple[int, bool]:
    """Apply both window caps by CLAMPING length; never by dropping a dump."""
    length = max(0, int(requested))
    capped = min(length, MAX_CONSENSUS_WINDOW)
    if n_dumps > 0:
        capped = min(capped, MAX_WINDOW_TOTAL_BYTES // n_dumps)
    return capped, capped < length


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def _flat_projection(
    length: int, start: int, size: int, n_dumps: int,
    classes: Optional[Sequence[int]],
) -> WindowProjection:
    """The projection for a coordinate that IS the offset in every dump.

    Both the flat (``file_offset``) consensus and the no-consensus fallback put
    byte ``k`` of every dump in correspondence with byte ``k`` of every other,
    so the window is ONE segment up to the shortest dump and a gap past it.
    ``layout_row`` is ``-1`` (there is no aligned layout) and every ``vas``
    entry is ``-1`` — the same "no virtual address" answer
    :meth:`ConsensusVector.slab_to_va` gives, because there genuinely is none.

    ``classes`` is ``None`` for the no-consensus path, which leaves every entry
    ``-1``. It must NEVER default to ``0``: ``0`` is INVARIANT, a measurement
    nobody made.
    """
    covered = max(0, min(length, max(0, size - start)))
    segments: Tuple[AlignedSegment, ...] = ()
    gaps: Tuple[Tuple[int, int], ...] = ()
    if covered > 0:
        segments = (AlignedSegment(
            window_offset=0, length=covered, slab_offset=start,
            layout_row=-1, vas=tuple([-1] * n_dumps),
        ),)
    if covered < length:
        gaps = ((covered, length - covered),)
    window_classes = [-1] * length
    if classes is not None:
        for i in range(min(covered, len(classes))):
            window_classes[i] = int(classes[i])
    return WindowProjection(
        anchor_index=-1, start=start, length=length,
        segments=segments, gaps=gaps, classes=tuple(window_classes),
    )


def _project_window(
    consensus: Optional[ConsensusVector],
    *,
    coordinate: str,
    anchor_index: int,
    anchor_va: int,
    start: int,
    length: int,
    n_dumps: int,
    flat_size: int,
) -> WindowProjection:
    """Resolve the requested window into segments + gaps + per-byte classes."""
    if coordinate == COORDINATE_RAW_FILE:
        return _flat_projection(length, start, flat_size, n_dumps, None)
    assert consensus is not None  # nosec B101 - both other coordinates imply one
    if coordinate == COORDINATE_FLAT:
        classes = consensus.classifications[start:start + length].tolist()
        return _flat_projection(length, start, consensus.size, n_dumps, classes)
    if anchor_index < 0:
        return consensus.project_slab_window(start, length)
    return consensus.project_va_window(anchor_index, anchor_va, length)


# ---------------------------------------------------------------------------
# Peer reads — one open per selected dump, all live at once
# ---------------------------------------------------------------------------


def _open_selected(
    stack: ExitStack,
    selected: Sequence[Tuple[int, str]],
    key_material_by_path: Optional[Dict[str, Any]],
) -> List[Any]:
    """Open every selected dump ONCE, re-entering the key scope per dump.

    ``key_material_scope`` binds ONE key material for the duration of the
    scope, so N peers with N different keys need N scopes — a single shared
    scope would hand every peer the first peer's key. The scope only has to be
    active across the OPEN; the reads that follow use the source it produced.
    """
    from memdiver.app.reader_cache import key_material_scope

    from .key_material import open_dump_source

    sources = []
    for _index, path in selected:
        if not Path(path).exists():
            raise FileNotFoundServiceError(f"File not found: {path}")
        km = _key_material_for(key_material_by_path, path)
        with key_material_scope(km):
            sources.append(stack.enter_context(open_dump_source(path, km or {})))
    return sources


def _key_material_for(
    key_material_by_path: Optional[Dict[str, Any]], path: str,
) -> Optional[Dict[str, Any]]:
    """The key material registered for ``path``, matched the way paths vary."""
    by_path = key_material_by_path or {}
    if not by_path:
        return None
    hit = by_path.get(path)
    if hit is None:
        hit = by_path.get(str(Path(path)))
    return hit or None


def _read_dump_window(
    source: Any,
    path: str,
    projection: WindowProjection,
    dump_index: int,
    length: int,
    coordinate: str,
    include_bytes: bool,
) -> Dict[str, Any]:
    """Fill ONE dump's slice of the window from an already-open source.

    Returns the per-dump block of the response: the window-coordinate bytes,
    the runs of it that are real (``bytes_valid``), the view its provenance
    offsets are expressed in, and its key state. A LOCKED dump yields
    ``bytes: None`` and an empty ``bytes_valid`` — and nothing else in the
    window is affected, because one peer nobody has the key for must not cost
    the operator every other peer's bytes.
    """
    from memdiver.core.service_result import KeyStatus

    key = KeyStatus.from_source(source)
    view = _peer_view(source, coordinate)
    block: Dict[str, Any] = {
        "dump_index": dump_index,
        "dump_path": path,
        "format": getattr(source, "format_name", None),
        "view": view,
        "bytes": None,
        "bytes_valid": [],
        "key_status": key.to_dict(),
        "offsets": {},
    }
    if not key.decrypted:
        # Locked BEFORE any bounds/read work, matching read_hex_raw_result's
        # ordering: an encrypted container without a key reads back EMPTY, and
        # "offset out of range" would be a misleading way to report that.
        return block

    buffer = bytearray(length)
    valid: List[Tuple[int, int]] = []
    offsets: Dict[int, int] = {}
    for segment in projection.segments:
        read_at = _segment_offset_in(source, view, segment, dump_index)
        if read_at is None:
            continue
        offsets[segment.window_offset] = read_at
        if not include_bytes:
            valid.append((segment.window_offset, segment.length))
            continue
        data = source.read_range(read_at, segment.length, view=view)
        if not data:
            continue
        buffer[segment.window_offset:segment.window_offset + len(data)] = data
        valid.append((segment.window_offset, len(data)))
    block["bytes_valid"] = [list(v) for v in valid]
    block["offsets"] = offsets
    if include_bytes:
        block["bytes"] = base64.b64encode(bytes(buffer)).decode("ascii")
    return block


def _segment_offset_in(
    source: Any, view: str, segment: AlignedSegment, dump_index: int,
) -> Optional[int]:
    """Where ``segment``'s first byte lives in ``source``'s ``view``, or None.

    Per SEGMENT, because adjacent aligned pages can have moved by different
    amounts between runs; one scalar per dump would be wrong in a way that
    reads as plausible bytes.
    """
    if segment.layout_row < 0:
        # A flat coordinate: the segment's slab offset IS every dump's offset.
        return segment.slab_offset
    if dump_index >= len(segment.vas):
        return None
    va = int(segment.vas[dump_index])
    if va < 0:
        return None
    offset = _translate_va(source, view, va=va)
    return offset if offset is not None and offset >= 0 else None


# ---------------------------------------------------------------------------
# Response shaping
# ---------------------------------------------------------------------------


def _segment_dicts(
    projection: WindowProjection,
    selected: Sequence[Tuple[int, str]],
    blocks: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Per-segment PROVENANCE: where each dump's bytes for that run came from."""
    out = []
    for segment in projection.segments:
        dumps = []
        for (dump_index, _path), block in zip(selected, blocks):
            aligned = segment.layout_row >= 0 and dump_index < len(segment.vas)
            dumps.append({
                "dump_index": dump_index,
                "va": int(segment.vas[dump_index]) if aligned else -1,
                "offset": int(block["offsets"].get(segment.window_offset, -1)),
            })
        out.append({
            "window_offset": segment.window_offset,
            "length": segment.length,
            "slab_offset": segment.slab_offset,
            "dumps": dumps,
        })
    return out


def _unclassified_report(paths: Sequence[str]) -> Tuple[Dict[str, Any], int]:
    """Alignment report for the no-consensus path, from SIZES alone.

    No bytes are read. The report is the real one — including the "without
    ASLR correction" warning when the sizes differ — because a window served
    with no consensus behind it is still a window whose correspondence the
    client has to be able to judge.
    """
    sizes = []
    for path in paths:
        try:
            sizes.append(Path(path).stat().st_size)
        except OSError:
            raise FileNotFoundServiceError(f"File not found: {path}")
    compared = min(sizes) if sizes else 0
    return flat_alignment_report(sizes, compared).to_dict(), compared


def _coordinate_of(consensus: Optional[ConsensusVector]) -> str:
    if consensus is None:
        return COORDINATE_RAW_FILE
    return COORDINATE_FLAT if consensus.msl_layout is None else COORDINATE_ALIGNED


def _require_classified(consensus: ConsensusVector) -> None:
    """409 when the vector carries no classifications to overlay.

    An incremental session that was never finalized is exactly this: a live
    Welford state with a variance but no classification array. Serving it would
    return a window whose every class is ``-1`` while claiming
    ``classified: true`` — the silent lie this endpoint exists to avoid.
    """
    if len(consensus.classifications) == 0:
        raise CapabilityError(
            "this consensus has no classifications yet; finalize the build "
            "before asking for an aligned window",
            category=ErrorCategory.PRECONDITION,
            status=409,
        )


def _resolve_anchor(
    consensus: Optional[ConsensusVector],
    coordinate: str,
    selected: Sequence[Tuple[int, str]],
    sources: Sequence[Any],
    anchor_path: Optional[str],
    anchor_view: str,
    offset: int,
    slab_offset: Optional[int],
) -> Dict[str, Any]:
    """Resolve the request's anchor from the ALREADY-OPEN sources.

    A dump anchor's navigable ``offset`` is converted to an absolute VA here —
    through the same :func:`_translate_va` every peer conversion runs in the
    other direction — so the projection only ever deals in VAs and slab
    offsets. Reading it off the open source rather than re-opening the file is
    what keeps the open count at one per selected dump.
    """
    if anchor_path is None:
        start = 0 if slab_offset is None else int(slab_offset)
        return _anchor_dict("slab", None, -1, "slab", start, -1, -1, start)

    if anchor_view not in NAVIGABLE_VIEWS:
        raise CapabilityError(
            f"Unknown view: {anchor_view!r} (expected one of {NAVIGABLE_VIEWS})"
        )
    index, source = _anchor_source(consensus, selected, sources, anchor_path)
    if getattr(source, "format_name", "") == "msl" and anchor_view == "raw":
        raise CapabilityError(
            "view='raw' names a block header inside an .msl container, not the "
            "byte at that address; anchor on 'va' instead.",
        )
    _require_anchor_unlocked(source)
    span_start = _va_span_start(source) or 0

    if coordinate != COORDINATE_ALIGNED:
        if anchor_view == "va":
            raise CapabilityError(
                "an aligned-VA window is only available for an aligned "
                "consensus (module-offset or virtual-address). This build used "
                "raw file offsets, which carry no virtual addresses to anchor "
                "on.",
            )
        return _anchor_dict(
            "dump", anchor_path, index, anchor_view, int(offset), -1,
            span_start, int(offset),
        )

    va = _translate_va(source, anchor_view, offset=int(offset))
    if va is None or not _va_is_addressable(source, va):
        raise OffsetOutOfRangeError(
            "anchor offset does not name an addressable byte",
            details={"offset": offset, "view": anchor_view,
                     "format": getattr(source, "format_name", None)},
        )
    return _anchor_dict(
        "dump", anchor_path, index, anchor_view, int(offset), int(va),
        span_start, -1,
    )


def _va_is_addressable(source: Any, va: int) -> bool:
    """Whether ``va`` falls inside a captured run of ``source``.

    The ``"va"`` view is a sparse span, so ``span_start + offset`` is arithmetic
    that always succeeds; this is the bounds check that makes it mean something.
    """
    return any(run_va <= va < run_va + run for run_va, run, _o in _vas_runs(source))


def _require_anchor_unlocked(source: Any) -> None:
    """A locked ANCHOR is fatal — unlike a locked peer, which is reported.

    Everything in the window is measured from the anchor's coordinate, and a
    locked container has no regions, so its VA span is ``(0, 0)`` and every
    address derived from it would be fiction.
    """
    from memdiver.core.service_result import KeyStatus

    key = KeyStatus.from_source(source)
    if not key.decrypted:
        raise EncryptedDumpLockedError(key.hint or "anchor dump is locked")


def _anchor_source(
    consensus: Optional[ConsensusVector],
    selected: Sequence[Tuple[int, str]],
    sources: Sequence[Any],
    anchor_path: str,
) -> Tuple[int, Any]:
    """The anchor's ``(dump_index, open source)``, or a 404-shaped raise."""
    target = Path(anchor_path)
    for position, (index, path) in enumerate(selected):
        if path == anchor_path or Path(path) == target:
            return index, sources[position]
    if consensus is not None:
        index = consensus.dump_index_for_path(anchor_path)
        if index >= 0:
            raise FileNotFoundServiceError(
                f"anchor dump is part of the consensus but not of the selected "
                f"subset: {anchor_path}"
            )
        raise FileNotFoundServiceError(
            f"anchor dump is not part of this consensus: {anchor_path}"
        )
    raise FileNotFoundServiceError(
        f"anchor dump is not one of the named dumps: {anchor_path}"
    )


def _anchor_dict(
    kind: str, anchor_path: Optional[str], anchor_index: int, view: str,
    offset: int, va: int, span_start: int, slab_offset: int,
) -> Dict[str, Any]:
    return {
        "kind": kind,
        "dump_path": anchor_path,
        "dump_index": anchor_index,
        "view": view,
        "offset": offset,
        "va": va,
        "va_span_start": span_start,
        "slab_offset": slab_offset,
    }


# ---------------------------------------------------------------------------
# The ONE compute function
# ---------------------------------------------------------------------------


def aligned_window_from_vector(
    consensus: Optional[ConsensusVector],
    *,
    anchor_path: Optional[str] = None,
    anchor_view: str = "va",
    offset: int = 0,
    slab_offset: Optional[int] = None,
    length: int = 1024,
    dumps: Optional[Sequence[Any]] = None,
    include_bytes: bool = True,
    key_material_by_path: Optional[Dict[str, Any]] = None,
    session: Optional[ToolSession] = None,
) -> Dict[str, Any]:
    """Project one window across every selected dump and read it back.

    :param consensus: The built vector whose correspondence the window is
        expressed in, or ``None`` for the LABELLED no-consensus path
        (``classified: false``, every class ``-1``).
    :param anchor_path: Dump whose view ``offset`` is a coordinate in. ``None``
        anchors on the aligned slab instead (``slab_offset``).
    :param anchor_view: The anchor's navigable view. ``"raw"`` is refused for
        an ``.msl`` anchor (see the module docstring).
    :param offset: Offset of the window's first byte in the anchor's view.
    :param slab_offset: Slab-coordinate anchor; mutually exclusive with
        ``anchor_path``.
    :param length: Requested window length; CLAMPED by the two window caps.
    :param dumps: Subset selector — indices into the build order, or dump
        paths. With ``consensus=None`` these ARE the dumps (paths only).
    :param include_bytes: ``False`` returns coordinates and classes but no
        base64 payload.
    :param key_material_by_path: ``{dump_path: open_dump kwargs}``, applied one
        dump at a time.
    :param session: Accepted for producer-signature symmetry; this producer is
        stateless and does not read it.
    :returns: The aligned-window payload — see Invariant W1 in the module
        docstring.
    """
    del session  # stateless; the parameter exists for producer symmetry
    if anchor_path is not None and slab_offset is not None:
        raise CapabilityError("a window is anchored on a dump OR on the slab, not both")
    if consensus is not None:
        _require_classified(consensus)

    coordinate = _coordinate_of(consensus)
    selected = _select_dumps(consensus, dumps)
    requested_length = max(0, int(length))
    window_length, truncated = _clamp_length(requested_length, len(selected))

    flat_size = 0
    if consensus is None:
        alignment, flat_size = _unclassified_report([p for _i, p in selected])
    else:
        alignment = consensus.alignment_report.to_dict()

    with ExitStack() as stack:
        sources = _open_selected(stack, selected, key_material_by_path)
        anchor = _resolve_anchor(
            consensus, coordinate, selected, sources, anchor_path, anchor_view,
            offset, slab_offset,
        )
        projection = _project_window(
            consensus,
            coordinate=coordinate,
            anchor_index=anchor["dump_index"] if anchor["kind"] == "dump" else -1,
            anchor_va=int(anchor["va"]),
            start=int(anchor["slab_offset"]) if anchor["kind"] == "slab"
            else int(anchor["offset"]),
            length=window_length,
            n_dumps=len(selected),
            flat_size=flat_size,
        )
        blocks = [
            _read_dump_window(
                source, path, projection, index, window_length, coordinate,
                include_bytes,
            )
            for (index, path), source in zip(selected, sources)
        ]

    anchor["slab_offset"] = (
        projection.segments[0].slab_offset if projection.segments else -1
    )
    segments = _segment_dicts(projection, selected, blocks)
    for block in blocks:
        block.pop("offsets", None)

    return {
        "consensus_id": None,
        "classified": consensus is not None,
        "alignment": alignment,
        "anchor": anchor,
        "requested_length": requested_length,
        "length": window_length,
        "truncated": truncated,
        "classes": list(projection.classes),
        "gaps": [list(g) for g in projection.gaps],
        "segments": segments,
        "dumps": blocks,
    }


def aligned_window_result(
    session: ToolSession,
    *,
    dump_paths: Optional[Sequence[str]] = None,
    anchor_path: Optional[str] = None,
    anchor_view: str = "va",
    offset: int = 0,
    slab_offset: Optional[int] = None,
    length: int = 1024,
    normalize: bool = False,
    classify: bool = True,
    include_bytes: bool = True,
    key_material_by_path: Optional[Dict[str, Any]] = None,
) -> "ServiceResult":
    """Build a consensus over ``dump_paths`` and serve one aligned window.

    ``classify=False`` skips the build entirely and takes the labelled
    no-consensus path: ``classified: false``, ``method: "file_offset"``, a real
    coverage report from the file sizes, and every class ``-1`` — never ``0``,
    because ``0`` is INVARIANT, a claim nobody measured.

    NOTE(shared key material): ``engine.consensus_service.build_consensus``
    takes ONE ``key_material`` mapping for ALL paths — it has no per-path
    channel. The PEER READS here are per-path (each dump is opened inside its
    own ``key_material_scope``), so a set of differently-keyed dumps reads back
    correctly; only the BUILD is constrained. When the per-path mapping resolves
    to a single distinct key material covering every path, it is forwarded;
    when it does not, the build runs unkeyed rather than silently keying dump B
    with dump A's key. :func:`_shared_key_material` says so in the log.
    """
    from memdiver.core.service_result import Resolution, ServiceResult, StatusBlock

    paths = [str(p) for p in (dump_paths or [])]
    consensus: Optional[ConsensusVector] = None
    if classify:
        if len(paths) < 2:
            raise CapabilityError("Need at least 2 dumps to build a consensus")
        from memdiver.engine.consensus_service import build_consensus

        consensus = build_consensus(
            paths,
            normalize=normalize,
            key_material=_shared_key_material(paths, key_material_by_path),
        )

    payload = aligned_window_from_vector(
        consensus,
        anchor_path=anchor_path,
        anchor_view=anchor_view,
        offset=offset,
        slab_offset=slab_offset,
        length=length,
        dumps=None if consensus is not None else paths,
        include_bytes=include_bytes,
        key_material_by_path=key_material_by_path,
        session=session,
    )
    locked = [d for d in payload["dumps"] if not d["key_status"]["decrypted"]]
    resolution = Resolution.PARTIAL if locked else Resolution.OK
    return ServiceResult(payload=payload, status=StatusBlock(resolution=resolution))


def _shared_key_material(
    paths: Sequence[str], key_material_by_path: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """The ONE key material ``build_consensus`` can take, or ``None``.

    See the NOTE in :func:`aligned_window_result`: the build has a single
    key-material channel for all N paths. When every path is covered and every
    supplied mapping is equal, forwarding it is exactly right. Otherwise there
    is no honest single answer, so nothing is forwarded — the build then reads
    the locked containers as empty, which its own callers already surface,
    rather than this producer inventing a key assignment.
    """
    present = [_key_material_for(key_material_by_path, p) for p in paths]
    supplied = [km for km in present if km]
    if not supplied:
        return None
    first = supplied[0]
    if len(supplied) == len(paths) and all(km == first for km in supplied):
        return dict(first)
    logger.warning(
        "aligned window: the %d dumps carry differing (or partial) key "
        "material, but build_consensus takes ONE mapping for all paths; "
        "building unkeyed",
        len(paths),
    )
    return None
