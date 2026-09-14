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

``bytes_valid`` is a PRESENCE claim about the dump, not a byte count of the
read: a source may PAD a sparse read to the full requested length (``.msl``'s
``view="va"`` does), and a padded ``0x00`` must never read as "this dump holds
``0x00`` here". The runs therefore come from
:func:`~memdiver.core.dump_source.read_range_with_validity` and are per
CAPTURED RUN, so ONE segment may contribute several of them — and a byte the
dump never captured is outside all of them even though it sits inside a
segment. The wire form is unchanged: ``[[start, len], ...]`` in window
coordinates, ascending.

Where the dumps DISAGREE
------------------------
``variants`` is computed HERE and nowhere else, because the per-dump read loop
is the only place in the backend where all N dumps' bytes exist simultaneously:
``ConsensusVector`` stores variance and classifications, not bytes, and
``build_consensus`` closes its sources before it returns.

``variants`` is per index like ``classes``: how many DISTINCT values the
present dumps hold, ``0`` where nobody is present and ``1`` where every present
dump agrees. It is therefore also the disagreement answer: an index is a
DIFFER iff ``variants[i] >= 2``, which says at least two dumps are present
there AND at least two present values disagree — a byte only one dump holds
counts ``1``, because absence is a different finding and flagging it would fill
the overlay with every unmapped hole in every dump. There is deliberately no
second boolean field saying the same thing: two wire fields that must always
agree are two fields that can drift. ``variants`` is weight-independent on
purpose — the weighted-plurality "consensus byte" answers live to the
operator's per-dump weights and so stays a client concern.

Which coordinate a window is WALKED in
--------------------------------------
``anchor_view="vas"`` is the dense stream of a dump's captured bytes, so VAS
offset ``k+1`` is the byte after ``k`` even when the two sit in regions
megabytes apart in VA. Such a window is therefore walked run-to-run
(``ConsensusVector.project_vas_window``) and stays contiguous across a
captured-run boundary; walking it VA-linearly would march into unmapped VA and
report bytes every dump captured as a gap. ``anchor_view="va"`` — the
single-dump overlay's own coordinate — remains VA-linear.

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
import bisect
import logging
from contextlib import ExitStack
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

import numpy as np

from memdiver.core.dump_source import read_range_with_validity
from memdiver.core.variance import ByteClass
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

#: Ceiling on how many class regions ONE page may carry, and the default page
#: size. A ``min_length=1`` STRUCTURAL query over an 11 MB slab has hundreds of
#: thousands of regions; the page is what keeps the response (and the DOM that
#: renders it) bounded, and ``next_after`` is how the rest is reached.
MAX_REGIONS_PER_PAGE = 500
DEFAULT_REGIONS_PER_PAGE = 200

#: The three-class union that ``classes=None`` means, and the name a caller
#: spells it with. Real key material is class-MIXED (a measured 48-byte TLS 1.2
#: secret is 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL bytes), so a
#: single-class query SHATTERS a real secret into shards no ``min_length``
#: keeps. See :func:`class_regions_from_vector`.
NON_INVARIANT_CLASSES: Tuple[ByteClass, ...] = (
    ByteClass.STRUCTURAL, ByteClass.POINTER, ByteClass.KEY_CANDIDATE,
)
CLASS_UNION_ALIAS = "non_invariant"

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


def _unknown_view_error(view: str) -> CapabilityError:
    """The ONE refusal for a ``view`` an offset cannot name a byte in.

    Built in one place because the same operator typo used to surface as two
    different HTTP statuses depending on which entry point saw it: the two
    producers raised :class:`CapabilityError` (INVALID_INPUT, which
    ``api.main._capability_error_handler`` maps to **400**) while
    :func:`_translate_va`'s fall-through raised a bare ``ValueError``, which
    escapes that funnel entirely and reaches the client as an unhandled
    **500** — "the server is broken" for what is a misspelled request field.

    ``CapabilityError`` is therefore the correct type everywhere: a ``view``
    outside :data:`NAVIGABLE_VIEWS` is invalid INPUT, and it is the only type
    the transport-agnostic funnel can classify. No caller is affected today —
    both ``ValueError`` sites are unreachable behind the entry-point guards
    (see :func:`_require_navigable_view`) — and the one test that pins the
    message (``tests/test_consensus_class_regions.py``) already expects
    ``CapabilityError``.
    """
    return CapabilityError(
        f"Unknown view: {view!r} (expected one of {NAVIGABLE_VIEWS})"
    )


def _require_navigable_view(view: str) -> str:
    """Guard form of :func:`_unknown_view_error`, for the request entry points.

    Called where a ``view`` first arrives from a caller — :func:`_resolve_anchor`
    and :func:`class_regions_from_vector` — so every deeper refusal is a
    defence in depth rather than the primary check.
    """
    if view not in NAVIGABLE_VIEWS:
        raise _unknown_view_error(view)
    return view


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
    ``(va, length, chunk)`` while the regioned / gcore sources yield
    ``(start_va, end_va, file_offset)``. Only the VA halves differ; the third
    element is derived the SAME way for both — by accumulating run lengths in
    iteration order — because that is what ``view="vas"`` means to every one
    of these sources (``GCoreDumpSource._vas_cum``,
    ``_RegionedRawSource._cum_offsets``): the captured runs laid end to end.

    The yielded ``file_offset`` is deliberately NOT used as the VAS offset.
    For a regioned raw ``.bin`` the two happen to coincide (the bin IS the
    concatenation) but for an ELF core they differ by the header + program
    table — so trusting it sent every gcore ``"vas"`` read past its target by
    the size of the ELF prologue, at real bytes with the wrong address.

    Runs come out in ascending ``vas_offset``, which is the contract
    :meth:`ConsensusVector._walk_vas_window` documents.
    """
    tabulate = getattr(source, "captured_runs", None)
    if callable(tabulate):
        # The source can hand over its run table directly. Walking
        # ``iter_ranges`` for it instead COPIES every captured byte in the
        # container to keep three integers per run.
        yield from tabulate()
        return
    is_msl = getattr(source, "format_name", "") == "msl"
    flat = 0
    for first, second, _third in source.iter_ranges():
        va = int(first)
        run = int(second) if is_msl else int(second) - va
        if run <= 0:
            continue
        yield (va, run, flat)
        flat += run


def _vas_run_table(source: Any) -> Tuple[Tuple[int, int, int], ...]:
    """:func:`_vas_runs` materialized ONCE per source per request.

    Both a correctness enabler and a large win. ``_vas_runs`` walks
    ``source.iter_ranges()``, and ``MslReader.read_block_payload`` has no
    payload cache — so every call DECOMPRESSES every region of the container.
    ``_translate_va``, ``_va_is_addressable`` and ``_segment_offset_in`` each
    triggered that, several times per dump per window chunk. Computing the
    table once and threading it through those three costs one pass.
    """
    return tuple(_vas_runs(source))


def _translate_va(
    source: Any,
    view: str,
    *,
    runs: Optional[Sequence[Tuple[int, int, int]]],
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

    ``runs`` is ``source``'s already-materialized :func:`_vas_run_table` and is
    REQUIRED, with no default: a caller that forgot it used to fall back to
    re-walking (and, for an ``.msl``, re-decompressing) the container once per
    segment, and nothing failed — it just got slow. ``None`` is the right value
    for a view that needs no table, which is every view but ``"vas"``; the
    callers resolve the view and the table from the same ``_peer_view`` answer,
    so a ``"vas"`` translation always arrives with a real one.
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
        table = runs or ()
        if va is not None:
            target_va = int(va)
            for run_va, run, vas_offset in table:
                if run_va <= target_va < run_va + run:
                    return vas_offset + (target_va - run_va)
            return None
        target_off = int(offset or 0)
        for run_va, run, vas_offset in table:
            if vas_offset <= target_off < vas_offset + run:
                return run_va + (target_off - vas_offset)
        return None

    if view == "raw":
        # A flat dump has no virtual addresses, and an `.msl`'s raw view is the
        # container — `va_to_file_offset` would answer with a block header, not
        # the byte. Refusing keeps that read unreachable by accident.
        return None

    raise _unknown_view_error(view)


def _va_span_start(source: Any) -> Optional[int]:
    """Base VA of the ``"va"`` view, or ``None`` when the source has none.

    Prefers the source's own narrow accessor over ``metadata()``. The dict is
    not free: an ``.msl``'s carries ``vas_size``, which on a cold source view
    is a full pass over the container — a measured 15 ms to answer a question
    that costs 0.0004 ms directly, paid once per pane per request. Sources
    without the accessor keep the dict path, which is why the key is read
    rather than assumed.
    """
    narrow = getattr(source, "va_span_start", None)
    if callable(narrow):
        start = narrow()
        return None if start is None else int(start)
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
        index = dump_index_for(consensus, entry)
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


def dump_index_for(consensus: ConsensusVector, entry: Any) -> int:
    """Index of ``entry`` (an int index or a dump path) in the build order.

    PUBLIC on purpose, for the same reason ``app.composition.raise_if_locked``
    is: ``api.routers.analysis._reject_dumps_outside_consensus`` has to resolve
    a selector EXACTLY the way :func:`_select_dumps` does, or a request passes
    the router's gate and is then rejected by the producer (or vice versa) over
    a difference in path spelling. Sharing the resolver is right; a router
    reaching for another module's private name to do it is worse than the
    duplication it replaces.
    """
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
        take = min(covered, len(classes))
        if take > 0:
            # One slice assignment, not `take` indexed assignments: a 16 KiB
            # window must not cost 16384 Python round trips to copy a list of
            # ints into a list of ints. ``tolist()`` when the caller handed us
            # a numpy array, so the entries stay plain ``int`` either way.
            head = classes[:take]
            to_list = getattr(head, "tolist", None)
            window_classes[:take] = to_list() if callable(to_list) else head
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
    anchor_view: str = "va",
    anchor_runs: Sequence[Tuple[int, int, int]],
) -> WindowProjection:
    """Resolve the requested window into segments + gaps + per-byte classes.

    A ``"vas"`` anchor is walked in the dump's DENSE VAS stream, so ``start``
    is the VAS offset the client asked for and a window crossing a
    captured-run boundary stays contiguous. A ``"va"`` anchor stays VA-linear
    — that is the single-dump overlay's own coordinate — and is unchanged.
    """
    if coordinate == COORDINATE_RAW_FILE:
        return _flat_projection(length, start, flat_size, n_dumps, None)
    assert consensus is not None  # nosec B101 - both other coordinates imply one
    if coordinate == COORDINATE_FLAT:
        classes = consensus.classifications[start:start + length].tolist()
        return _flat_projection(length, start, consensus.size, n_dumps, classes)
    if anchor_index < 0:
        return consensus.project_slab_window(start, length)
    if coordinate == COORDINATE_ALIGNED and anchor_view == "vas":
        # An EMPTY run table must NOT fall through to the VA-linear walk. That
        # walk is the wrong answer for a VAS anchor by construction — it
        # marches off the end of the first captured run into unmapped VA and
        # reports bytes every dump captured as a gap — and "the anchor has no
        # captured runs" is not evidence for it; it is evidence there is
        # nothing to walk. ``_walk_vas_window`` yields nothing for an empty
        # table, so this is an EMPTY projection (all gaps, every class -1),
        # which is the honest answer. ``_va_is_addressable`` rejects an empty
        # table in ``_resolve_anchor`` first, so this cannot fire today; the
        # point is that the wrong walk is now unreachable by construction
        # rather than one guard away.
        return consensus.project_vas_window(
            anchor_index, anchor_runs, start, length,
        )
    return consensus.project_va_window(anchor_index, anchor_va, length)


# ---------------------------------------------------------------------------
# Peer reads — one open per selected dump, all live at once
# ---------------------------------------------------------------------------


def _open_one(
    stack: ExitStack,
    path: str,
    key_material_by_path: Optional[Dict[str, Any]],
) -> Any:
    """Open ONE dump on ``stack``, inside its OWN key-material scope.

    The one-scope-per-dump rule, asserted in exactly one place.
    ``key_material_scope`` binds ONE key material for the duration of the
    scope, so N dumps with N different keys need N scopes — a single shared
    scope would hand every dump the first one's key. The scope only has to be
    active across the OPEN; the reads that follow use the source it produced,
    which stays live until the caller's ``ExitStack`` unwinds.
    """
    from memdiver.app.reader_cache import key_material_scope

    from .key_material import open_dump_source

    if not Path(path).exists():
        raise FileNotFoundServiceError(f"File not found: {path}")
    km = _key_material_for(key_material_by_path, path)
    with key_material_scope(km):
        return stack.enter_context(open_dump_source(path, km or {}))


def _open_selected(
    stack: ExitStack,
    selected: Sequence[Tuple[int, str]],
    key_material_by_path: Optional[Dict[str, Any]],
) -> List[Any]:
    """Open every selected dump ONCE, re-entering the key scope per dump.

    Per-dump open + key scope is :func:`_open_one`; this is the loop over the
    selection, in selection order, so ``sources[i]`` pairs with
    ``selected[i]``.
    """
    return [
        _open_one(stack, path, key_material_by_path) for _index, path in selected
    ]


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
    runs: Optional[Sequence[Tuple[int, int, int]]],
) -> Tuple[Dict[str, Any], Optional[bytes], List[Tuple[int, int]]]:
    """Fill ONE dump's slice of the window from an already-open source.

    Returns ``(block, raw_bytes, valid_runs)``.

    ``block`` is the per-dump block of the RESPONSE: the window-coordinate
    bytes, the runs of it that are real (``bytes_valid``), the view its
    provenance offsets are expressed in, and its key state. A LOCKED dump
    yields ``bytes: None`` and an empty ``bytes_valid`` — and nothing else in
    the window is affected, because one peer nobody has the key for must not
    cost the operator every other peer's bytes.

    ``raw_bytes`` / ``valid_runs`` are the SAME window handed back beside the
    block rather than inside it, for :func:`_cross_dump_runs` — this loop is
    the only point at which all N windows exist at once. ``valid_runs`` is the
    RUN list, the same shape ``bytes_valid`` goes out as, not a dense mask:
    the runs are what the read produced, and densifying is the reducer's job,
    once, in numpy. They used to be smuggled through the block as ``_buffer``
    and ``_valid`` and popped by convention before the response was built; a
    forgotten pop shipped private fields on the wire. Returning them beside
    the block makes that impossible instead of merely discouraged.
    ``raw_bytes`` is ``None`` for a locked dump and for ``include_bytes=False``
    — nothing was read, so there is nothing that could manufacture a
    disagreement.

    ``bytes_valid`` is a PRESENCE claim, so it comes from
    :func:`~memdiver.core.dump_source.read_range_with_validity` rather than
    from ``len(data)``: ``MslDumpSource._read_range_va`` PADS its result to the
    full requested length, so a byte value is not evidence that the dump ever
    captured that address. One segment may therefore contribute SEVERAL runs.

    ``runs`` is this source's ``_vas_run_table``, threaded in so an ``.msl`` is
    not re-decompressed once per segment. REQUIRED, with no default: the
    fallback it replaced cost one full container walk PER SEGMENT and failed
    nothing, so a caller that forgot it was invisible. ``None`` is the right
    value for a peer whose view is not ``"vas"`` and needs no table.
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
        return block, None, []

    buffer = bytearray(length)
    valid: List[Tuple[int, int]] = []
    offsets: Dict[int, int] = {}
    for segment in projection.segments:
        read_at = _segment_offset_in(source, view, segment, dump_index, runs)
        if read_at is None:
            continue
        offsets[segment.window_offset] = read_at
        if not include_bytes:
            # No read happened, so there is nothing to claim as present. This
            # matches the locked-peer convention (``bytes: None`` + an empty
            # ``bytes_valid``); which bytes the window COVERS is already
            # carried by ``segments[]``.
            continue
        data, captured = read_range_with_validity(
            source, read_at, segment.length, view=view,
        )
        if not data:
            continue
        buffer[segment.window_offset:segment.window_offset + len(data)] = data
        for start_in_data, run_length in captured:
            # ``read_range_with_validity`` documents its runs as RESULT-RELATIVE
            # and both in-tree producers keep them inside the read, so this is a
            # belt-and-braces clamp for a third-party ``register_dump_source``.
            # Spelled exactly as :func:`_dense_valid` spells it, so the file has
            # ONE clamp idiom rather than two that could disagree.
            begin = max(0, int(start_in_data))
            stop = min(segment.length, begin + int(run_length))
            if stop > begin:
                valid.append((segment.window_offset + begin, stop - begin))
    block["bytes_valid"] = [list(v) for v in valid]
    block["offsets"] = offsets
    if not include_bytes:
        return block, None, []
    block["bytes"] = base64.b64encode(bytes(buffer)).decode("ascii")
    return block, bytes(buffer), valid


def _segment_offset_in(
    source: Any,
    view: str,
    segment: AlignedSegment,
    dump_index: int,
    runs: Optional[Sequence[Tuple[int, int, int]]],
) -> Optional[int]:
    """Where ``segment``'s first byte lives in ``source``'s ``view``, or None.

    Per SEGMENT, because adjacent aligned pages can have moved by different
    amounts between runs; one scalar per dump would be wrong in a way that
    reads as plausible bytes.

    ``runs`` is ``source``'s :func:`_vas_run_table`, forwarded so a window with
    many segments walks the container's region table once rather than once per
    segment. REQUIRED, with no default, for the reason
    :func:`_read_dump_window` gives; ``None`` is the right value for a view
    that needs no table.
    """
    if segment.layout_row < 0:
        # A flat coordinate: the segment's slab offset IS every dump's offset.
        return segment.slab_offset
    if dump_index >= len(segment.vas):
        return None
    va = int(segment.vas[dump_index])
    if va < 0:
        return None
    offset = _translate_va(source, view, runs=runs, va=va)
    return offset if offset is not None and offset >= 0 else None


# ---------------------------------------------------------------------------
# Cross-dump disagreement: the one place all N windows exist at once
# ---------------------------------------------------------------------------


def _dense_valid(runs: Sequence[Sequence[int]], length: int) -> Any:
    """One dump's ``bytes_valid`` runs as a dense presence mask."""
    mask = np.zeros(length, dtype=bool)
    for run in runs:
        begin = max(0, int(run[0]))
        stop = min(length, begin + int(run[1]))
        if stop > begin:
            mask[begin:stop] = True
    return mask


def _cross_dump_runs(
    buffers: Sequence[bytes],
    valids: Sequence[Sequence[Sequence[int]]],
    length: int,
) -> List[int]:
    """How many DISTINCT values the selected dumps hold, per window index.

    Computed here and nowhere else because the per-dump ``blocks`` loop is the
    only point in the backend at which all N dumps' bytes exist simultaneously:
    ``ConsensusVector`` keeps variance and classifications, not bytes, and
    ``build_consensus`` closes its sources before it returns.

    :param buffers: One window-coordinate byte string per COMPARABLE dump —
        locked peers and an ``include_bytes=False`` call contribute none, so a
        dump whose bytes were never read can never manufacture a disagreement.
    :param valids: The matching ``bytes_valid`` RUN lists, ``[[start, len]]``
        in window coordinates. Presence comes from these and never from the
        byte values: a source may PAD a sparse read with ``0x00`` (``.msl``'s
        ``view="va"`` does), so a ``0x00`` inside no run is an absent byte.
    :returns: ``variants``, per-index (mirroring ``classes``, not ``gaps``):
        the number of DISTINCT byte values among the dumps present, ``0`` where
        nobody is present and ``1`` where every present dump agrees.

    It is also the DISAGREEMENT answer, and the only one on the wire: an index
    is a differ iff ``variants[i] >= 2``. That is exactly "**at least two dumps
    are PRESENT there AND at least two present values disagree**" — a column
    with one present dump counts ``1`` and an empty one counts ``0``, so
    ``>= 2`` can only be reached by two present dumps holding two values. A
    byte only one dump holds is therefore NOT a differ: absence is a different
    finding from disagreement, and counting it would flag every unmapped hole
    in every dump and bury the real disagreements in false positives.

    Deliberately weight-independent — it counts values, not a plurality —
    because the weighted "consensus byte" must answer live to the operator's
    per-dump weights and so cannot round-trip to the server per keystroke.

    Vectorised, not a column loop: a 16 KiB window must not become 16384 Python
    iterations. Absent entries are mapped to a sentinel ABOVE every byte value
    (256, hence ``int16``) so that sorting each column parks them after every
    real value; the first ``present[i]`` rows of sorted column ``i`` are then
    exactly that column's present values in order, and its distinct count is
    one plus the number of adjacent changes among those rows.
    """
    if length <= 0:
        return []
    if not buffers:
        return [0] * length
    if len(buffers) < 2:
        # One dump cannot disagree with itself. The stack/sort/diff below would
        # run in full to produce a column of ``1``s and ``0``s; the variant
        # count is just "is this byte present", which is the mask itself.
        return _dense_valid(valids[0], length).astype(np.int64).tolist()

    values = np.stack([
        np.frombuffer(bytes(buffer), dtype=np.uint8)[:length] for buffer in buffers
    ])
    masks = np.stack([_dense_valid(runs, length) for runs in valids])
    present = masks.sum(axis=0)

    ordered = np.where(masks, values.astype(np.int16), 256)
    ordered.sort(axis=0)
    distinct = (present > 0).astype(np.int64)
    if ordered.shape[0] > 1:
        changed = ordered[1:] != ordered[:-1]
        # Only rows the column actually filled: row r counts iff r < present.
        inside = np.arange(1, ordered.shape[0])[:, None] < present[None, :]
        distinct = distinct + (changed & inside).sum(axis=0)

    # ``present >= 2`` is NOT a separate condition to apply here: a column with
    # ``present == 0`` scores ``0`` and one with ``present == 1`` scores
    # ``(present > 0) == 1`` plus no in-range adjacent change, so ``distinct``
    # can only reach 2 where two dumps are present. The disagreement rule is
    # already inside this number.
    #
    # ``distinct`` is an int64 ndarray; ``tolist()`` converts the whole array
    # in C and already yields plain ``int``. The per-element ``int(...)``
    # comprehension it replaces was ~80% of this function's cost at N=2.
    return distinct.tolist()


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
) -> Tuple[Dict[str, Any], Tuple[Tuple[int, int, int], ...]]:
    """Resolve the request's anchor from the ALREADY-OPEN sources.

    A dump anchor's navigable ``offset`` is converted to an absolute VA here —
    through the same :func:`_translate_va` every peer conversion runs in the
    other direction — so the projection only ever deals in VAs and slab
    offsets. Reading it off the open source rather than re-opening the file is
    what keeps the open count at one per selected dump.

    Returns ``(anchor, anchor_runs)``. ``anchor_runs`` is the anchor source's
    :func:`_vas_run_table`, computed HERE because this function already needs
    it twice (the offset -> VA conversion and the addressability check) and
    :func:`_project_window` needs the very same table to walk a ``"vas"``
    window run-to-run. Empty for a slab anchor, which addresses no dump.
    """
    if anchor_path is None:
        start = 0 if slab_offset is None else int(slab_offset)
        return _anchor_dict("slab", None, -1, "slab", start, -1, -1, start), ()

    _require_navigable_view(anchor_view)
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
        ), ()

    anchor_runs = _vas_run_table(source)
    va = _translate_va(source, anchor_view, runs=anchor_runs, offset=int(offset))
    if va is None or not _va_is_addressable(source, va, anchor_runs):
        raise OffsetOutOfRangeError(
            "anchor offset does not name an addressable byte",
            details={"offset": offset, "view": anchor_view,
                     "format": getattr(source, "format_name", None)},
        )
    return _anchor_dict(
        "dump", anchor_path, index, anchor_view, int(offset), int(va),
        span_start, -1,
    ), anchor_runs


def _va_is_addressable(
    source: Any, va: int, runs: Sequence[Tuple[int, int, int]],
) -> bool:
    """Whether ``va`` falls inside a captured run of ``source``.

    The ``"va"`` view is a sparse span, so ``span_start + offset`` is arithmetic
    that always succeeds; this is the bounds check that makes it mean something.

    ``runs`` is ``source``'s already-materialized :func:`_vas_run_table`, and
    is required: the optional-with-recompute form it replaced re-walked the
    whole container for any caller that forgot it, silently.
    """
    return any(run_va <= va < run_va + run for run_va, run, _o in runs)


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
        anchor, anchor_runs = _resolve_anchor(
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
            anchor_view=str(anchor["view"]),
            anchor_runs=anchor_runs,
        )
        # One region-table pass per source, up front: a peer read in the
        # ``"vas"`` view needs it per segment, and `_vas_runs` decompresses
        # the whole container every time it is walked.
        peer_runs = [
            _vas_run_table(source)
            if _peer_view(source, coordinate) == "vas" else None
            for source in sources
        ]
        reads = [
            _read_dump_window(
                source, path, projection, index, window_length, coordinate,
                include_bytes, runs,
            )
            for (index, path), source, runs in zip(selected, sources, peer_runs)
        ]

    blocks = [block for block, _buffer, _valid in reads]
    anchor["slab_offset"] = (
        projection.segments[0].slab_offset if projection.segments else -1
    )
    segments = _segment_dicts(projection, selected, blocks)
    # Only dumps whose bytes were actually READ are comparable: a locked peer
    # returned no buffer, so its zeros can never manufacture a disagreement,
    # and ``include_bytes=False`` leaves nothing to compare at all.
    comparable = [
        (buffer, valid) for _block, buffer, valid in reads if buffer is not None
    ]
    variants = _cross_dump_runs(
        [buffer for buffer, _valid in comparable],
        [valid for _buffer, valid in comparable],
        window_length,
    )
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
        "variants": variants,
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


# ---------------------------------------------------------------------------
# Class regions: the JUMPABLE occurrence list
# ---------------------------------------------------------------------------


def _parse_class_spec(classes: Optional[Sequence[Any]]) -> Tuple[ByteClass, ...]:
    """Coerce a surface-level class query to a ByteClass tuple.

    Accepts the lower-case histogram names every surface already speaks
    (``"invariant"``, ``"structural"``, ``"pointer"``, ``"key_candidate"``),
    raw integer codes, and the alias ``"non_invariant"`` for the three-class
    union. ``None`` IS that union — see :func:`class_regions_from_vector` for
    why that is the only defensible default.

    The name -> code translation is delegated to
    :func:`~memdiver.engine.candidate_pipeline.resolve_byte_classes`, the one
    place in the codebase that owns it, so a typo is rejected here with the
    identical message ``analyze_candidates`` rejects it with.
    """
    if classes is None:
        return NON_INVARIANT_CLASSES
    items: List[Any] = (
        [classes] if isinstance(classes, (str, int)) else list(classes)
    )
    if not items:
        raise CapabilityError(
            "at least one byte class is required; omit `classes` entirely for "
            f"the {CLASS_UNION_ALIAS!r} union"
        )
    expanded: List[Any] = []
    for item in items:
        if isinstance(item, str) and item.strip().lower().replace(
            "-", "_",
        ) == CLASS_UNION_ALIAS:
            expanded.extend(NON_INVARIANT_CLASSES)
        else:
            expanded.append(item)

    from memdiver.engine.candidate_pipeline import resolve_byte_classes

    try:
        return resolve_byte_classes(expanded)
    except ValueError as exc:
        raise CapabilityError(f"{exc} (or {CLASS_UNION_ALIAS!r})") from None


def _va_offset_index(
    source: Any,
    view: str,
    runs: Optional[Sequence[Tuple[int, int, int]]],
) -> Callable[[int], int]:
    """A VA -> navigable-offset function for ``source``, built ONCE.

    :func:`_translate_va` answers the same question, but a ``"vas"`` lookup
    there WALKS the run table linearly per call. A window asks it a handful of
    times; a region page asks it twice per row, so 200 rows over a container
    with a large region table is millions of iterations for one request. This
    materializes the table once, sorts it by VA and bisects — O(R log R) once
    plus O(log R) per lookup instead of O(R) per lookup.

    Sorted by ``va_start`` explicitly rather than trusted: :func:`_vas_runs`
    guarantees ascending ``vas_offset`` (that is the ``_walk_vas_window``
    contract) but NOT ascending VA, and bisecting an unsorted key would answer
    plausible offsets for the wrong addresses.

    The returned callable closes over plain integer lists, so it stays valid
    after ``source`` is closed. ``-1`` — never a plausible number — for an
    address the view cannot name, which is the same refusal
    :meth:`ConsensusVector.slab_to_va` makes.

    ``runs`` is ``source``'s :func:`_vas_run_table` and is REQUIRED for the
    reason the rest of this module's ``runs`` parameters are: recomputing it
    behind a forgetful caller costs a whole container walk and fails nothing.
    ``None`` is the right value for the ``"va"`` view, which needs no table.

    Only the two VA-bearing views arrive here. The sole caller
    (:func:`_region_locator`) returns ``None`` for ``"raw"`` and for a ``"va"``
    anchor with no span, and the entry point already ran
    :func:`_require_navigable_view`, so the guards those cases used to need
    were dead code standing between the reader and the two real answers.
    """
    if view == "va":
        span_start = _va_span_start(source)
        # ``_region_locator`` refuses a spanless ``"va"`` anchor before it gets
        # here, so this narrowing is for the type checker, not for a case.
        assert span_start is not None  # nosec B101 - see above
        base = span_start

        def _va_linear(va: int) -> int:
            out = int(va) - base
            return out if out >= 0 else -1

        return _va_linear

    table = sorted(runs or ())
    starts = [int(entry[0]) for entry in table]
    ends = [int(entry[0]) + int(entry[1]) for entry in table]
    bases = [int(entry[2]) for entry in table]

    def _va_bisect(va: int) -> int:
        va = int(va)
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or va >= ends[i]:
            return -1
        return bases[i] + (va - starts[i])

    return _va_bisect


def _open_anchor(
    stack: ExitStack,
    anchor_path: str,
    key_material_by_path: Optional[Dict[str, Any]],
) -> Any:
    """Open the anchor dump alone, with its own key material.

    The same one-scope-per-dump open :func:`_open_selected` performs — now
    literally the same code (:func:`_open_one`), so the rule cannot be
    asserted in one place and drift in the other. A region page reads NO bytes
    from any peer, so only the anchor is opened.
    """
    return _open_one(stack, anchor_path, key_material_by_path)


def _region_locator(
    consensus: ConsensusVector,
    source: Any,
    coordinate: str,
    anchor_index: int,
    anchor_view: str,
) -> Optional[Callable[[int], Tuple[int, int]]]:
    """``slab_offset -> (anchor_va, anchor_offset)``, or ``None`` if unanswerable.

    ``None`` is the envelope's ``jumpable: false``: the anchor genuinely has no
    coordinate in which these slab offsets name a byte, so every row would
    carry ``-1`` and a client that hid the "jump" affordance would be right to.

    * ALIGNED build — the slab maps to a VA per dump
      (:meth:`ConsensusVector.slab_to_va`), and the VA maps to an offset in the
      anchor's view (:func:`_va_offset_index`). ``"raw"`` answers nothing.
    * FLAT build — there are no virtual addresses at all, but the slab offset
      IS every dump's offset in the very stream the build compared, so the
      answer is the slab offset itself and ONLY in that stream's own view
      (:func:`_peer_view`). Asking for ``"va"`` on a flat build is the case the
      aligned-window route refuses outright; here it is simply not jumpable.
    """
    if coordinate == COORDINATE_ALIGNED:
        if anchor_view == "raw" or not consensus.msl_layout:
            return None
        if anchor_view == "va" and _va_span_start(source) is None:
            return None
        runs: Optional[Tuple[Tuple[int, int, int], ...]] = None
        if anchor_view == "vas":
            runs = _vas_run_table(source)
            if not runs:
                return None
        to_offset = _va_offset_index(source, anchor_view, runs)

        def _aligned(slab_offset: int) -> Tuple[int, int]:
            va = consensus.slab_to_va(anchor_index, slab_offset)
            return (va, to_offset(va) if va >= 0 else -1)

        return _aligned

    if anchor_view != _peer_view(source, coordinate):
        return None

    def _flat(slab_offset: int) -> Tuple[int, int]:
        return (-1, int(slab_offset))

    return _flat


def _region_row(
    region: Any,
    wanted: Tuple[ByteClass, ...],
    classifications: Any,
    locate: Optional[Callable[[int], Tuple[int, int]]],
) -> Dict[str, Any]:
    """One region as the wire row, anchor coordinates and all.

    ``anchor_offset_end`` is resolved from the region's LAST byte rather than
    from ``anchor_offset + length``: a region is contiguous in SLAB space, but
    ``msl_layout`` rows are per page and :meth:`slab_to_va` is linear only
    WITHIN a row, so a region spanning a row boundary can be two disjoint runs
    in the anchor's own coordinate. ``anchor_contiguous`` states which it is,
    so a caller that highlights ``[offset, offset_end)`` knows whether that
    range is the region or merely contains it.
    """
    start, end = int(region.start), int(region.end)
    anchor_va, anchor_offset = locate(start) if locate is not None else (-1, -1)
    anchor_offset_end = -1
    if locate is not None and end > start:
        _last_va, last_offset = locate(end - 1)
        if last_offset >= 0:
            anchor_offset_end = last_offset + 1
    length = end - start
    return {
        "slab_start": start,
        "slab_end": end,
        "length": length,
        "classification": region.classification,
        "mean_variance": float(region.mean_variance),
        "class_counts": _region_class_counts(classifications, start, end, wanted),
        "anchor_va": int(anchor_va),
        "anchor_offset": int(anchor_offset),
        "anchor_offset_end": int(anchor_offset_end),
        "anchor_contiguous": (
            anchor_offset >= 0
            and anchor_offset_end >= 0
            and anchor_offset_end - anchor_offset == length
        ),
    }


def _region_class_counts(
    classifications: Any, start: int, end: int, wanted: Tuple[ByteClass, ...],
) -> Dict[str, int]:
    """Per-class byte counts inside ONE region — union queries only.

    A single-class query already answers this with ``length``, so it returns
    ``{}`` rather than a tautology. For a union it is the fact that makes the
    union defensible: it shows the analyst that a 48-byte row really is
    22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL and not a POINTER run that
    drifted in. Classes contributing nothing are omitted.
    """
    if len(wanted) < 2:
        return {}
    codes = np.asarray(classifications[start:end], dtype=np.uint8)
    if codes.size == 0:
        return {}
    counts = np.bincount(codes, minlength=len(ByteClass))
    return {
        klass.name.lower(): int(counts[int(klass)])
        for klass in wanted
        if int(klass) < len(counts) and counts[int(klass)]
    }


#: The orders :func:`class_regions_from_vector` can serve.
#:
#: ``"offset"`` is slab order, the only one whose cursor is a slab offset; the
#: length sorts page by RANK instead. Kept as one tuple so the producer, the
#: request model and the CLI choices cannot drift into three vocabularies.
REGION_SORTS = ("offset", "length_desc", "length_asc")


def class_regions_from_vector(
    consensus: ConsensusVector,
    *,
    classes: Optional[Sequence[Any]] = None,
    min_length: int = 8,
    max_length: int = 0,
    sort: str = "offset",
    after: int = -1,
    limit: int = DEFAULT_REGIONS_PER_PAGE,
    anchor_path: Optional[str] = None,
    anchor_view: str = "va",
    include_anchor_offsets: bool = True,
    key_material_by_path: Optional[Dict[str, Any]] = None,
    session: Optional[ToolSession] = None,
) -> Dict[str, Any]:
    """Every occurrence of a consensus class, paginated AND jumpable.

    The list behind "show me every key candidate": one page of regions, each
    carrying not just its slab coordinates but the offset a hex viewer can be
    scrolled to (``anchor_offset`` is ``scrollToOffset``'s argument verbatim).

    WHY AN OFFSET AND NOT JUST A VA. The overlay navigates in ``"vas"`` while
    the single viewer navigates in ``"va"``, so a VA alone would force every
    client to re-implement :func:`_translate_va` — the client-side slab -> VA ->
    offset arithmetic this module exists to delete, and the source of both
    shipped overlay bugs. ``-1`` means "no honest answer" (the convention
    :meth:`ConsensusVector.slab_to_va` set) and the envelope's
    ``anchor.jumpable`` says so once for the whole page, so a client never has
    to infer a refusal from a sea of ``-1``s.

    ``anchor_offset`` is ``-1`` for: a raw/flat build queried in ``"va"``, a
    LOCKED anchor (reported, never raised — a page of regions is still a useful
    answer without a key), and a slab offset outside ``msl_layout``.

    WHY ``classes=None`` IS THE NON-INVARIANT UNION. Real key material is
    class-MIXED: a measured 48-byte TLS 1.2 secret classifies as 22
    KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL bytes. A naive
    ``classes=["key_candidate"]`` query therefore does not return that secret —
    it SHATTERS it into 3-byte shards that every sane ``min_length`` discards.
    The union over STRUCTURAL/POINTER/KEY_CANDIDATE keeps it whole (see
    :meth:`ConsensusVector._class_runs`), so it is the default, and
    ``"non_invariant"`` names it explicitly for a caller that passes classes.

    :param classes: Class names, raw codes, or ``"non_invariant"``; ``None``
        is the non-invariant union.
    :param min_length: Shortest region to report, in bytes.
    :param max_length: Longest region to report; 0 is unbounded.
    :param sort: ``"offset"`` (slab order, the default), ``"length_desc"``
        (longest first) or ``"length_asc"``. See the cursor note below.
    :param after: EXCLUSIVE cursor — pass the previous page's ``next_after``;
        ``-1`` starts from the beginning. Its UNIT depends on ``sort``: a slab
        offset for ``"offset"``, a rank index for the length sorts, because
        rank order and slab order are unrelated and a slab cursor cannot page
        a ranked list. Treat it as OPAQUE: clients hand it back untouched and
        only ever compare it to ``-1``, which is what makes the two meanings
        safe to share one field.
    :param limit: Rows per page, clamped to :data:`MAX_REGIONS_PER_PAGE`.
    :param anchor_path: Dump whose coordinate the jump offsets are in.
    :param anchor_view: That dump's navigable view.
    :param include_anchor_offsets: ``False`` skips opening the anchor entirely
        (no offsets, ``jumpable: false``) — the cheap path for a caller that
        only wants counts.
    :param key_material_by_path: ``{dump_path: open_dump kwargs}``; only the
        anchor's entry is ever used, since no peer is read.
    :param session: Accepted for producer-signature symmetry; unused.
    """
    del session  # stateless; the parameter exists for producer symmetry
    _require_classified(consensus)
    wanted = _parse_class_spec(classes)
    coordinate = _coordinate_of(consensus)
    limit = max(1, min(int(limit), MAX_REGIONS_PER_PAGE))
    min_length = max(1, int(min_length))
    max_length = max(0, int(max_length))
    if sort not in REGION_SORTS:
        raise CapabilityError(
            f"Unknown sort: {sort!r} (expected one of {', '.join(REGION_SORTS)})")

    anchor: Dict[str, Any] = {
        "dump_path": anchor_path,
        "dump_index": -1,
        "view": anchor_view,
        "jumpable": False,
    }
    locate: Optional[Callable[[int], Tuple[int, int]]] = None
    if anchor_path is not None:
        _require_navigable_view(anchor_view)
        index = consensus.dump_index_for_path(anchor_path)
        if index < 0:
            raise FileNotFoundServiceError(
                f"anchor dump is not part of this consensus: {anchor_path}"
            )
        anchor["dump_index"] = index
        if include_anchor_offsets:
            with ExitStack() as stack:
                source = _open_anchor(stack, anchor_path, key_material_by_path)
                # A LOCKED anchor is REPORTED, not fatal — unlike the aligned
                # window, nothing here is read through it, so the regions
                # themselves are unaffected and only the jump offsets are lost.
                from memdiver.core.service_result import KeyStatus

                if KeyStatus.from_source(source).decrypted:
                    locate = _region_locator(
                        consensus, source, coordinate, index, anchor_view,
                    )
                anchor["jumpable"] = locate is not None

    total = consensus.count_regions(
        wanted, min_length=min_length, max_length=max_length,
    )
    classifications = consensus.classifications
    rows: List[Dict[str, Any]] = []
    truncated = False
    after = int(after)
    if sort == "offset":
        for region in consensus.iter_regions(
            wanted, min_length=min_length, max_length=max_length, after=after,
        ):
            if len(rows) == limit:
                # One region past the page: the ONLY honest way to know whether
                # a next page exists without counting past the cursor again.
                truncated = True
                break
            rows.append(_region_row(region, wanted, classifications, locate))
        next_after = int(rows[-1]["slab_start"]) if truncated and rows else -1
    else:
        # RANK-ordered page. `after` is the rank of the last row the caller
        # already has, so the next one starts at `after + 1` — the same
        # exclusive-cursor contract the slab path uses, in the only unit that
        # can page a list whose order is unrelated to slab offsets.
        rank_offset = after + 1 if after >= 0 else 0
        ranked = consensus.rank_regions_by_length(
            wanted, min_length=min_length, max_length=max_length,
            descending=(sort == "length_desc"),
            offset=rank_offset, limit=limit,
        )
        # `rank_regions_by_length` returns one row past the page for exactly
        # this test, mirroring the slab path's lookahead.
        truncated = len(ranked) > limit
        rows = [
            _region_row(region, wanted, classifications, locate)
            for region in ranked[:limit]
        ]
        next_after = rank_offset + len(rows) - 1 if truncated and rows else -1

    return {
        "consensus_id": None,
        "coordinate": coordinate,
        "alignment": consensus.alignment_report.to_dict(),
        "anchor": anchor,
        "classes": [klass.name.lower() for klass in wanted],
        "union": len(wanted) > 1,
        "min_length": min_length,
        "max_length": max_length,
        "sort": sort,
        "after": after,
        "next_after": next_after,
        "total": total,
        "returned": len(rows),
        "truncated": truncated,
        # The WHOLE-BUILD class histogram, so the chip counts beside the list
        # ("key_candidate 1.2M") arrive with the first page instead of costing
        # a second round trip to POST /consensus.
        "counts": consensus.classification_counts(),
        "regions": rows,
    }


def class_regions_result(
    session: ToolSession,
    *,
    dump_paths: Optional[Sequence[str]] = None,
    classes: Optional[Sequence[Any]] = None,
    min_length: int = 8,
    max_length: int = 0,
    sort: str = "offset",
    after: int = -1,
    limit: int = DEFAULT_REGIONS_PER_PAGE,
    anchor_path: Optional[str] = None,
    anchor_view: str = "va",
    include_anchor_offsets: bool = True,
    normalize: bool = False,
    key_material_by_path: Optional[Dict[str, Any]] = None,
) -> "ServiceResult":
    """Build a consensus over ``dump_paths`` and serve one page of regions.

    The ``*_result`` half of the pair, for a caller that holds paths rather
    than a built vector — the CLI and MCP surfaces, and the ``dump_paths``
    branch of ``POST /consensus/regions``.

    NOTE(shared key material): identical to :func:`aligned_window_result` —
    ``build_consensus`` takes ONE ``key_material`` mapping for all paths, so
    :func:`_shared_key_material` forwards the per-path mapping only when it
    resolves to a single key covering every path, and otherwise builds unkeyed
    rather than silently keying dump B with dump A's key.
    """
    from memdiver.core.service_result import Resolution, ServiceResult, StatusBlock

    paths = [str(p) for p in (dump_paths or [])]
    if len(paths) < 2:
        raise CapabilityError("Need at least 2 dumps to build a consensus")

    from memdiver.engine.consensus_service import build_consensus

    consensus = build_consensus(
        paths,
        normalize=normalize,
        key_material=_shared_key_material(paths, key_material_by_path),
    )
    payload = class_regions_from_vector(
        consensus,
        classes=classes,
        min_length=min_length,
        max_length=max_length,
        sort=sort,
        after=after,
        limit=limit,
        anchor_path=anchor_path,
        anchor_view=anchor_view,
        include_anchor_offsets=include_anchor_offsets,
        key_material_by_path=key_material_by_path,
        session=session,
    )
    # PARTIAL when an anchor was asked for and could not be answered: the rows
    # are complete but carry no navigable offsets, which is exactly the
    # "answered, but not fully" state the status block exists to name.
    asked_for_offsets = anchor_path is not None and include_anchor_offsets
    resolution = (
        Resolution.PARTIAL
        if asked_for_offsets and not payload["anchor"]["jumpable"]
        else Resolution.OK
    )
    return ServiceResult(payload=payload, status=StatusBlock(resolution=resolution))
