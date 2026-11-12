"""Module-relative page keys for VA-capable process views (``module_relative``).

Two independently launched instances of one program map the same modules at
different ASLR bases, so absolute-VA keys (``va:{va}``) line up almost nothing
between them. This module re-keys each captured page by WHAT it is rather than
WHERE it is, from the process's own VMA list:

* a page of a file-backed VMA -> ``mod:{path}:{va - module_base:#014x}``, where
  ``module_base`` is the lowest ``vm_start`` among that file's VMAs (the
  native ``.msl`` key style of ``core.region_align.build_dump_region_map``);
* the anonymous VMA directly adjacent to a module's LAST file VMA (its
  ``.bss``) -> ``mod:{path}:bss:+{va - bss_start:#014x}``;
* ``[heap]`` -> ``heap:+{va - heap_start:#014x}``, heap start being the lowest
  heap VMA start (the kernel's ``start_brk`` page);
* every other anonymous VMA (mmap arenas, thread stacks, ``[stack]``,
  ``[vdso]``) -> no key: the page is left OUT of the alignment.

Why other anonymous memory is dropped rather than given an ordinal key: an
ordinal (``anon:{size}:{n}``) only corresponds when both processes created
their anonymous mappings in the same order and size, which independent
launches do not guarantee (threads, arenas and lazily-loaded plugins race).
A false correspondence silently classifies unrelated bytes as variance; a
dropped page is counted in ``bytes_discarded`` and named by the
:data:`MODULE_RELATIVE_UNKEYED` diagnostic, which is the honest failure mode.

Offsets are zero-padded so :func:`core.region_align.align_dumps`' lexicographic
key ordering is also numeric ordering within a module.

The VMA listing comes from an image view's ``vmas()`` (``.mdview`` process
view) or from an image-EXTRACTED ``.msl``'s effective VAS map (which
``msl.image_extract`` writes one entry per VMA). No other source offers one.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Diagnostic code: captured bytes the module-relative scheme had no key for.
MODULE_RELATIVE_UNKEYED = "module_relative_unkeyed"

_OFFSET_FORMAT = "{:#014x}"


@dataclass(frozen=True)
class AlignmentVma:
    """The facts module-relative keying needs about one VMA."""

    start: int
    end: int
    name: str
    file_backed: bool
    is_heap: bool

    @property
    def is_module(self) -> bool:
        """A file mapping with a real path (``<unresolved>`` names never key)."""
        return self.file_backed and self.name.startswith("/")


# -- VMA listings ------------------------------------------------------------------

def alignment_vmas(source: Any) -> Optional[List[AlignmentVma]]:
    """The VMA listing *source* can be module-relative keyed by, else ``None``.

    ``None`` for every source that is not a process image view or an
    image-extracted ``.msl`` -- they keep the alignment they always had.
    """
    if getattr(source, "format_name", "") == "msl":
        return _extracted_msl_vmas(source)
    listing = getattr(source, "vmas", None)
    if not (callable(listing) and getattr(source, "supports_va_alignment", False)):
        return None
    vmas = [AlignmentVma(int(v.start), int(v.end), str(v.name or ""),
                         bool(getattr(v, "file_backed", False)),
                         bool(getattr(v, "is_heap", False)))
            for v in listing()]
    return vmas or None


def is_image_extracted_msl(source: Any) -> bool:
    """An ``.msl`` that ``msl.image_extract`` wrote from a process view."""
    if getattr(source, "format_name", "") != "msl":
        return False
    from memdiver.msl.source_format import reader_is_image_extracted
    return reader_is_image_extracted(source.get_reader())


def _extracted_msl_vmas(source: Any) -> Optional[List[AlignmentVma]]:
    if not is_image_extracted_msl(source):
        return None
    from memdiver.msl.enums import RegionType
    vas_map = source.get_reader().effective_vas_map()
    if vas_map is None:
        return None
    file_types = {int(RegionType.IMAGE), int(RegionType.MAPPED_FILE)}
    vmas = [AlignmentVma(int(e.base_addr), int(e.base_addr) + int(e.region_size),
                         str(e.mapped_path or ""),
                         int(e.region_type) in file_types,
                         int(e.region_type) == int(RegionType.HEAP))
            for e in vas_map.entries]
    return vmas or None


# -- layout comparison -------------------------------------------------------------

def module_bases(vmas: Sequence[AlignmentVma]) -> Dict[str, int]:
    """``{path: lowest vm_start}`` over the file-backed VMAs."""
    bases: Dict[str, int] = {}
    for vma in vmas:
        if vma.is_module:
            bases[vma.name] = min(bases.get(vma.name, vma.start), vma.start)
    return bases


def layouts_differ(listings: Sequence[Sequence[AlignmentVma]]) -> bool:
    """True when some module common to every listing sits at different bases.

    Different bases mean independent ASLR (separately launched processes);
    forked siblings inherit their parent's layout and keep ``virtual_address``.
    No common module at all is not evidence of anything: ``False``.
    """
    bases = [module_bases(vmas) for vmas in listings]
    if not bases:
        return False
    common = set(bases[0]).intersection(*bases[1:])
    return any(len({b[path] for b in bases}) > 1 for path in common)


# -- keying ------------------------------------------------------------------------

class ModuleRelativeKeyer:
    """Page VA -> module-relative key (or ``None``) for one process's VMAs."""

    def __init__(self, vmas: Sequence[AlignmentVma]) -> None:
        ordered = sorted(vmas, key=lambda v: v.start)
        self._spans = _keyed_spans(ordered)
        self._starts = [span[0] for span in self._spans]

    def __call__(self, va: int) -> Optional[str]:
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        start, end, prefix, base = self._spans[i]
        if va >= end:
            return None
        return prefix + _OFFSET_FORMAT.format(va - base)


def _keyed_spans(ordered: Sequence[AlignmentVma]
                 ) -> List[Tuple[int, int, str, int]]:
    """``(start, end, key_prefix, key_base)`` for every keyable VMA, by start."""
    bases = module_bases(ordered)
    last_start = {v.name: v.start for v in ordered if v.is_module}
    heap_starts = [v.start for v in ordered if v.is_heap]
    heap_base = min(heap_starts) if heap_starts else 0
    spans: List[Tuple[int, int, str, int]] = []
    prev: Optional[AlignmentVma] = None
    for vma in ordered:
        if vma.is_module:
            spans.append((vma.start, vma.end, f"mod:{vma.name}:", bases[vma.name]))
        elif vma.is_heap:
            spans.append((vma.start, vma.end, "heap:+", heap_base))
        elif _is_bss_of(vma, prev, last_start):
            assert prev is not None  # nosec B101 - _is_bss_of checked it
            spans.append((vma.start, vma.end, f"mod:{prev.name}:bss:+", vma.start))
        prev = vma
    return spans


def _is_bss_of(vma: AlignmentVma, prev: Optional[AlignmentVma],
               last_start: Dict[str, int]) -> bool:
    """Anonymous, directly adjacent to the previous VMA, which ends its module."""
    return (prev is not None and not vma.file_backed and prev.is_module
            and prev.end == vma.start and last_start[prev.name] == prev.start)


def unkeyed_diagnostic(unkeyed_bytes: Sequence[int]) -> Optional[Any]:
    """INFO ``Diagnostic`` naming the captured bytes left out per dump, if any."""
    if not any(unkeyed_bytes):
        return None
    from memdiver.core.service_result import Diagnostic, Severity
    total = sum(unkeyed_bytes)
    return Diagnostic(
        code=MODULE_RELATIVE_UNKEYED,
        message=(f"module_relative alignment left {total} captured bytes "
                 f"unaligned: anonymous memory outside heap and module .bss "
                 f"has no ASLR-invariant key across independent processes"),
        severity=Severity.INFO,
        details={"unkeyed_bytes": [int(n) for n in unkeyed_bytes]},
    )
