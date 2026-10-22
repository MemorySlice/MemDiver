"""Analysis-time region view filter for stored ``.msl`` dumps.

A *view filter* lets a full ``.msl`` be analysed as if only the selected
region categories existed, WITHOUT rewriting the file (contrast the
import-time selection in :mod:`memdiver.msl.region_select`, which drops
regions before they are written). It is a
:class:`~memdiver.msl.region_select.RegionSelection` applied to the regions
a reader already holds.

Classification is the stored-region rule shared with the import preview
(:func:`memdiver.msl.import_preview.msl_region_infos` ->
:func:`~memdiver.msl.region_select.classify_stored`): stored ``region_type``
+ ``protection`` + owning module path + the raw-provenance rule (a
raw-imported ``.msl`` is UNCLASSIFIED throughout) + trusted VAS_MAP mapping
names (:func:`memdiver.msl.import_preview.msl_classification_context`). An
``.msl`` carries no thread stack ranges, so STACK comes only from a stored
``RegionType.STACK`` or a stack mapping name.

Only ``.msl`` sources honour a view filter; raw / ELF-core / regioned-raw
sources carry no stored classification and ignore it.

The persisted / wire form of a filter is its :meth:`RegionSelection.to_note`
string (``"regions=heap,stack"``); :func:`coerce_region_filter` also accepts
the CLI-style spec (``"heap,stack"``). ``None`` means "no filter".
"""

from __future__ import annotations

import bisect
from typing import List, Optional, Sequence, Union

from memdiver.msl.region_select import (
    RegionInfo,
    RegionSelection,
    parse_selection,
)

RegionFilterLike = Union[None, str, RegionSelection]


def is_active(region_filter: Optional[RegionSelection]) -> bool:
    """True when *region_filter* would actually exclude something."""
    return region_filter is not None and not region_filter.is_all


def coerce_region_filter(value: RegionFilterLike) -> Optional[RegionSelection]:
    """Normalise a filter given as None / selection / note / spec string.

    ``"regions=..."`` strings are parsed with
    :meth:`RegionSelection.from_note`; anything else goes through
    :func:`parse_selection` (``"heap,stack"``, ``"all"``, ``"image"``).
    Blank strings mean ``None``. Raises ``ValueError`` on unknown names.
    """
    if value is None or isinstance(value, RegionSelection):
        return value
    if not isinstance(value, str):
        raise ValueError(f"region_filter must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        return None
    if text.startswith("regions="):
        return RegionSelection.from_note(text)
    return parse_selection(text)


def region_filter_note(value: RegionFilterLike) -> Optional[str]:
    """Persistable form: the ``to_note()`` string, or ``None`` for no filter.

    A selection of every category (``"all"``) is stored as ``None``, because
    it filters nothing.
    """
    selection = coerce_region_filter(value)
    if not is_active(selection):
        return None
    return selection.to_note()


def _module_lookup(reader):
    modules = sorted(
        (int(m.base_addr), int(m.base_addr) + int(m.module_size), m.path)
        for m in reader.collect_modules()
    )
    return [m[0] for m in modules], modules


def _owning_module_path(base: int, starts, modules) -> Optional[str]:
    idx = bisect.bisect_right(starts, base) - 1
    if idx >= 0 and modules[idx][0] <= base < modules[idx][1]:
        return modules[idx][2] or None
    return None


def stored_region_infos(reader, regions: Optional[Sequence] = None
                        ) -> List[RegionInfo]:
    """Classify *regions* (default: ``reader.collect_regions()``), in order.

    The returned list is parallel to *regions*.
    """
    from memdiver.msl.import_preview import (msl_classification_context,
                                             msl_region_infos)
    from memdiver.msl.page_map import count_captured_pages

    if regions is None:
        regions = reader.collect_regions()
    starts, modules = _module_lookup(reader)
    raw = []
    for r in regions:
        pages = r.page_intervals or r.page_states
        raw.append((
            int(r.base_addr), int(r.region_size), int(r.protection),
            int(r.region_type), count_captured_pages(pages) * int(r.page_size),
            _owning_module_path(int(r.base_addr), starts, modules),
        ))
    source_format, names, _ = msl_classification_context(reader)
    return msl_region_infos(raw, source_format, names)


def region_filter_mask(reader, region_filter: Optional[RegionSelection],
                       regions: Optional[Sequence] = None
                       ) -> Optional[List[bool]]:
    """Per-region inclusion flags parallel to *regions*, or ``None``.

    ``None`` means the filter is inactive (keep everything) so callers can
    skip the classification pass entirely.
    """
    if not is_active(region_filter):
        return None
    infos = stored_region_infos(reader, regions)
    return [region_filter.includes(info) for info in infos]
