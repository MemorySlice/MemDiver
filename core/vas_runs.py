"""The captured-run table of a VA-bearing dump source.

Shared by ``app.tools_consensus`` and ``engine.xref_pointers`` so the run-table
normalization lives in one place below both layers.
"""

from __future__ import annotations

from typing import Any, Iterator, Tuple


def vas_runs(source: Any) -> Iterator[Tuple[int, int, int]]:
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


def vas_run_table(source: Any) -> Tuple[Tuple[int, int, int], ...]:
    """:func:`vas_runs` materialized ONCE per source per request.

    Both a correctness enabler and a large win. ``vas_runs`` walks
    ``source.iter_ranges()``, and ``MslReader.read_block_payload`` has no
    payload cache — so every call DECOMPRESSES every region of the container.
    ``_translate_va``, ``_va_is_addressable`` and ``_segment_offset_in`` each
    triggered that, several times per dump per window chunk. Computing the
    table once and threading it through those three costs one pass.
    """
    return tuple(vas_runs(source))
