"""Import preview of an ``.mdview`` image view (the wizard's region step).

``msl.import_preview.preview_import`` sniffs a file's bytes, and an ``.mdview``
is a 4 KB descriptor — it would be listed as one opaque raw region. The
regions of an image view are the VMAs of a process view, so they are read from
the open source and classified with the SAME category rules an import uses
(:func:`memdiver.msl.import_preview.region_infos`). A physical or kernel view
has no VMA layout and nothing to select: the preview says so with a
machine-readable ``selection_applicable`` flag the UI turns into its own text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.core.image.run_index import RunState
from memdiver.app.key_material import open_dump_source
from memdiver.core.image.view_descriptor import ViewDescriptor, ViewKind
from memdiver.msl.enums import Protection, RegionType
from memdiver.msl.import_preview import ImportPreview, LAYOUT_NATIVE, region_infos
from memdiver.msl.region_select import RegionSelection

#: ``ImportPreview.format`` of an image view (the source's ``format_name``).
IMAGE_VIEW_FORMAT = "image_view"

_PROTECTION_BITS = (("r", Protection.READ), ("w", Protection.WRITE),
                    ("x", Protection.EXECUTE))

_RawRegion = Tuple[int, int, int, int, int, Optional[str]]


def _protection(text: str) -> int:
    """Protection flags of a vol3-style ``"rwx"`` string (``"r-x"``, ``"RW"``...)."""
    letters = text.lower()
    return int(sum(bit for ch, bit in _PROTECTION_BITS if ch in letters))


def _region_type(vma: Any, protection: int) -> int:
    if vma.is_heap:
        return int(RegionType.HEAP)
    if vma.name.startswith("[stack"):
        return int(RegionType.STACK)
    if vma.file_backed and vma.name.startswith("/"):
        executable = protection & Protection.EXECUTE
        return int(RegionType.IMAGE if executable else RegionType.MAPPED_FILE)
    return int(RegionType.ANONYMOUS)


def _captured_bytes(start: int, end: int, captured: Sequence[Tuple[int, int]]) -> int:
    return sum(max(0, min(end, hi) - max(start, lo)) for lo, hi in captured)


def _vma_regions(vmas: Sequence[Any], layer_runs: Sequence[Any]) -> List[_RawRegion]:
    captured = [(r.start, r.end) for r in layer_runs if r.state is RunState.CAPTURED]
    regions: List[_RawRegion] = []
    for vma in vmas:
        protection = _protection(vma.protection)
        path = vma.name if vma.name.startswith("/") else None
        regions.append((vma.start, vma.end - vma.start, protection,
                        _region_type(vma, protection),
                        _captured_bytes(vma.start, vma.end, captured), path))
    return regions


def _payload(kind: ViewKind, regions: List[Any],
             selection: Optional[RegionSelection]) -> Dict[str, Any]:
    preview = ImportPreview(format=IMAGE_VIEW_FORMAT, is_msl=False, regions=regions,
                            layout=LAYOUT_NATIVE, platform="linux",
                            platform_source="format")
    return {**preview.to_dict(selection), "view_kind": kind.value,
            # Nothing filters a Vol3LayerSource (open_dump only filters .msl), so the
            # selection is never applied to an image view; a process view still shows
            # its mappings by kind. Region choice happens on extraction to .msl.
            "selection_applicable": False}


def image_view_preview(path: "str | Path",
                       selection: Optional[RegionSelection]) -> Dict[str, Any]:
    """``ImportPreview.to_dict()`` for an ``.mdview``, plus two keys.

    ``view_kind`` is the descriptor's view (``process`` / ``kernel`` /
    ``physical``); ``selection_applicable`` is False when there are no VMAs to
    choose between, so the UI can say that instead of showing an empty table.
    Only a process view is opened (its VMAs are the regions); the other two are
    answered from the descriptor, so previewing never pays an ISF load.
    """
    kind = ViewDescriptor.read(Path(path)).view
    if kind is not ViewKind.PROCESS:
        return _payload(kind, [], selection)
    with open_dump_source(str(path), {}) as source:
        raw = _vma_regions(source.vmas(), source.layer_runs())
    return _payload(kind, region_infos(raw, ()), selection)


def is_image_view_path(path: "str | Path") -> bool:
    return Path(path).suffix == ".mdview"
