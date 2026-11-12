"""Physical-frame classification of process memory in a full Linux x86_64 image.

A frame mapped by two sibling processes has ONE content, so it cannot hold a value that
differs between them. Frames private to one process are therefore the candidate set for a
per-instance secret. Shared frames are labelled, never dropped: they can still hold a
*group* secret (a key loaded before ``fork()``, a shared-memory session cache).

Three pieces, usable from a stock-vol3 plugin and from MemDiver core alike:

* :func:`page_frames` walks a vol3 Intel translation layer ONCE per page and yields a
  :class:`PageFrame` per 4 KiB subpage (a 2 MiB/1 GiB leaf yields one record per 4 KiB
  subpage with its own PFN). It needs vol3's private ``_translate_entry(va)`` for the raw
  leaf entry (flags, swap entries); without it, it falls back to the public
  ``layer.mapping()`` (PFNs only, flags unknown, swap entries invisible).
* :func:`zero_page_pfns` resolves the frames of ``empty_zero_page`` and the huge zero page.
* :func:`classify_frames` is pure: it labels every page of every member with a share class.

Tiers of evidence (decided_by):

* ``T0``, one process: ``W=1`` in a private VMA proves the page exclusive (PageAnonExclusive,
  5.19+). ``W=0`` never proves sharing (a sibling may have exited, uffd-wp / clear_refs may
  have cleared W): it only sets ``possibly_shared``.
* ``T1``, the sibling intersection: a PFN mapped by >= 2 members is shared. A PFN that no other
  member maps is private *relative to the group*.
* ``special``: the zero page(s) are ``zero``, never "shared by all".

``smear_conflict``: a PFN that >= 2 members map while one of their private-VMA PTEs has W=1.
Acquisition is not atomic, so the frame was reused between the walks: trust neither label.

Caller contract: pass ONE member per address space (dedup tasks by ``mm``). Two threads of
one process passed as two members make every page look shared.

Import rule of this directory: standard library, ``volatility3`` and sibling modules only;
Python 3.8 syntax.
"""
import collections
import logging
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from volatility3.framework import exceptions

vollog = logging.getLogger(__name__)

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PMD_SIZE = 1 << 21
HUGE_ZERO_PAGES = PMD_SIZE >> PAGE_SHIFT  # the huge zero page = 512 base frames

# x86 page-table entry bits (arch/x86/include/asm/pgtable_types.h).
PTE_PRESENT = 1 << 0
PTE_RW = 1 << 1
PTE_ACCESSED = 1 << 5
PTE_DIRTY = 1 << 6
PTE_PSE = 1 << 7
PTE_PROTNONE = 1 << 8      # aliases _PAGE_GLOBAL; meaningful only when P=0
PTE_SPECIAL = 1 << 9
PTE_SOFT_DIRTY = 1 << 11
PTE_SAVED_DIRTY = 1 << 58  # 6.6+ shadow-stack kernels move D here on write-protect
_ENTRY_MASK = (1 << 64) - 1
_PTE_NONE_IGNORED = PTE_DIRTY | PTE_ACCESSED  # pte_none() ignores the KNL-erratum bits
DEFAULT_PHYS_BITS = 52

# vm_area_struct.vm_flags bits (include/linux/mm.h).
VM_WRITE = 0x2
VM_SHARED = 0x8

# Page states (PageFrame.state).
RESIDENT = "resident"
SWAPPED = "swapped"
NOT_RESIDENT = "not_resident"

# Share classes (ClassifiedPage.share_class).
PRIVATE_DIRTY = "private_dirty"
PRIVATE_CLEAN = "private_clean"
PRIVATE_FILE_COW = "private_file_cow"
SHARED_LINEAGE = "shared_lineage"
SHARED_FILE = "shared_file"
SHMEM = "shmem"
ZERO = "zero"
SHARE_CLASSES = (PRIVATE_DIRTY, PRIVATE_CLEAN, PRIVATE_FILE_COW, SHARED_LINEAGE,
                 SHARED_FILE, SHMEM, ZERO, SWAPPED, NOT_RESIDENT)
PRIVATE_CLASSES = frozenset({PRIVATE_DIRTY, PRIVATE_CLEAN, PRIVATE_FILE_COW})
SHARED_CLASSES = frozenset({SHARED_LINEAGE, SHARED_FILE, SHMEM})

#: One walked page. ``length`` is 4096 for a resident or swapped subpage; a not-resident
#: record covers a whole absent block. ``entry`` is the raw leaf entry (the swap entry when
#: swapped), ``None`` when unknown (mapping() fallback, absent block). ``page_size`` is the
#: leaf size: 4 KiB, 2 MiB or 1 GiB.
PageFrame = collections.namedtuple("PageFrame", "va length pfn entry page_size state")

#: The VMA facts the classifier needs (MemDiver's ``core.image.adapters.Vma`` duck-types it).
VmaInfo = collections.namedtuple("VmaInfo", "start end vm_flags file_backed")

#: One classified page of one member.
ClassifiedPage = collections.namedtuple(
    "ClassifiedPage",
    "member va length pfn share_class decided_by smear_conflict possibly_shared dirty writable")

#: Result of :func:`classify_frames`: every page plus post-mortem smaps per member.
FrameClassification = collections.namedtuple("FrameClassification", "pages accounting")


# --- entry decoding ---------------------------------------------------------------------

def entry_is_none(entry: int) -> bool:
    """``pte_none()``: no page, no swap entry (A/D may linger on KNL-erratum CPUs)."""
    return not (entry & ~_PTE_NONE_IGNORED)


def entry_is_protnone(entry: int) -> bool:
    """A PROT_NONE / NUMA-hinting page: not present to the MMU but resident."""
    return not (entry & PTE_PRESENT) and bool(entry & PTE_PROTNONE)


def entry_is_resident(entry: int) -> bool:
    return bool(entry & PTE_PRESENT) or entry_is_protnone(entry)


def entry_is_writable(entry: Optional[int]) -> bool:
    return entry is not None and entry_is_resident(entry) and bool(entry & PTE_RW)


def entry_is_dirty(entry: Optional[int]) -> bool:
    """Hardware Dirty or the shadow-stack SavedDirty bit."""
    return entry is not None and entry_is_resident(entry) and bool(
        entry & (PTE_DIRTY | PTE_SAVED_DIRTY))


def entry_phys(entry: int, page_size: int = PAGE_SIZE, phys_bits: int = DEFAULT_PHYS_BITS) -> int:
    """Physical base of the leaf. Linux stores a PROT_NONE entry's PFN inverted (L1TF):
    ``pte_pfn()`` XORs the whole entry before masking, and so does this."""
    if entry_is_protnone(entry):
        entry ^= _ENTRY_MASK
    return entry & ((1 << phys_bits) - 1) & ~(page_size - 1)


# --- the walk -----------------------------------------------------------------------------

def page_frames(layer: Any, start: int, end: int) -> Iterator[PageFrame]:
    """One :class:`PageFrame` per 4 KiB subpage of ``[start, end)`` (absent blocks merged).

    One page-table walk per leaf: a 2 MiB leaf costs one ``_translate_entry`` call and
    yields 512 records. Falls back to ``layer.mapping()`` when the private API is missing
    or its signature changed.
    """
    start &= ~(PAGE_SIZE - 1)
    if end <= start:
        return
    if not _has_entry_api(layer, start):
        vollog.debug("layer %s has no usable _translate_entry; using mapping()",
                     getattr(layer, "name", "?"))
        yield from _mapping_frames(layer, start, end)
        return
    phys_bits = min(int(getattr(layer, "_maxphyaddr", DEFAULT_PHYS_BITS)), DEFAULT_PHYS_BITS)
    absent_start = None
    for frame in _entry_frames(layer, start, end, phys_bits):
        if frame.state == NOT_RESIDENT:
            absent_start = frame.va if absent_start is None else absent_start
            continue
        if absent_start is not None:
            yield _absent(absent_start, frame.va)
            absent_start = None
        yield frame
    if absent_start is not None:
        yield _absent(absent_start, end)


def _absent(lo: int, hi: int) -> PageFrame:
    return PageFrame(lo, hi - lo, None, None, PAGE_SIZE, NOT_RESIDENT)


def _has_entry_api(layer: Any, probe: int) -> bool:
    translate_entry = getattr(layer, "_translate_entry", None)
    if translate_entry is None:
        return False
    try:
        entry, position = translate_entry(probe)
        return isinstance(entry, int) and isinstance(position, int)
    except exceptions.InvalidAddressException:
        return True  # the API works; this address is just not mapped
    except (TypeError, ValueError):  # signature / return shape changed
        return False


def _entry_frames(layer: Any, start: int, end: int, phys_bits: int) -> Iterator[PageFrame]:
    va = start
    while va < end:
        try:
            entry, position = layer._translate_entry(va)
            leaf = 1 << (position + 1)
        except exceptions.PagedInvalidAddressException as exc:
            leaf = 1 << max(int(exc.invalid_bits), PAGE_SHIFT)
            entry = int(exc.entry)
            if not _upper_leaf(entry, leaf):  # empty or invalid table: whole block absent
                stop = min((va // leaf + 1) * leaf, end)
                yield _absent(va, stop)
                va = stop
                continue
        except exceptions.InvalidAddressException:
            yield _absent(va, va + PAGE_SIZE)
            va += PAGE_SIZE
            continue
        stop = min((va // leaf + 1) * leaf, end)
        yield from _leaf_frames(entry, leaf, va, stop, phys_bits)
        va = stop


def _upper_leaf(entry: int, block: int) -> bool:
    """A non-present upper-level entry that is still a page: a PROT_NONE huge leaf (a plain,
    non-Linux Intel layer refuses it) or a PMD swap/migration entry (only PMDs have those).
    A *present* entry here means vol3 rejected the next table (all-duplicate entries):
    nothing is mapped."""
    if entry & PTE_PRESENT or entry_is_none(entry):
        return False
    if entry_is_protnone(entry):
        return bool(entry & PTE_PSE)
    return block == PMD_SIZE


def _leaf_frames(entry: int, leaf: int, lo: int, hi: int, phys_bits: int) -> Iterator[PageFrame]:
    if entry_is_resident(entry):
        leaf_va = lo & ~(leaf - 1)
        base = entry_phys(entry, leaf, phys_bits)
        for va in range(lo, hi, PAGE_SIZE):
            yield PageFrame(va, PAGE_SIZE, (base + va - leaf_va) >> PAGE_SHIFT, entry, leaf,
                            RESIDENT)
    elif entry_is_none(entry):
        yield _absent(lo, hi)
    else:
        for va in range(lo, hi, PAGE_SIZE):
            yield PageFrame(va, PAGE_SIZE, None, entry, leaf, SWAPPED)


def _mapping_frames(layer: Any, start: int, end: int) -> Iterator[PageFrame]:
    """Public-API fallback: PFNs from ``mapping()``; flags and swap entries are unknown."""
    cursor = start
    for offset, size, mapped, _mapped_size, _below in layer.mapping(start, end - start,
                                                                   ignore_errors=True):
        lo, hi = max(offset, cursor), min(offset + size, end)
        if hi <= lo:
            continue
        if lo > cursor:
            yield _absent(cursor, lo)
        for va in range(lo, hi, PAGE_SIZE):
            yield PageFrame(va, PAGE_SIZE, (mapped + va - offset) >> PAGE_SHIFT, None,
                            PAGE_SIZE, RESIDENT)
        cursor = hi
    if cursor < end:
        yield _absent(cursor, end)


def vma_info(vma: Any) -> VmaInfo:
    """:class:`VmaInfo` of a vol3 ``vm_area_struct`` (unreadable ``vm_file`` = file-backed)."""
    try:
        file_backed = int(vma.vm_file) != 0
    except Exception:  # vol3 raises InvalidAddressException / AttributeError
        file_backed = True
    return VmaInfo(int(vma.vm_start), int(vma.vm_end), int(vma.vm_flags), file_backed)


def member_frames(layer: Any, vmas: Iterable[Any]) -> Iterator[Tuple[Any, PageFrame]]:
    """``(vma, frame)`` for every page of every VMA of one process layer."""
    for vma in vmas:
        for frame in page_frames(layer, vma.start, vma.end):
            yield vma, frame


# --- zero pages ---------------------------------------------------------------------------

def zero_page_pfns(context: Any, kernel: Any) -> Set[int]:
    """PFNs of ``empty_zero_page`` and of the huge zero page (when allocated)."""
    layer = context.layers[kernel.layer_name]
    pfns = set()
    if kernel.has_symbol("empty_zero_page"):
        try:
            phys, _below = layer.translate(kernel.get_absolute_symbol_address("empty_zero_page"))
            pfns.add(int(phys) >> PAGE_SHIFT)
        except exceptions.InvalidAddressException:
            vollog.warning("empty_zero_page does not translate; zero pages unlabelled")
    huge = _huge_zero_pfn(kernel)
    if huge is not None:
        pfns.update(range(huge, huge + HUGE_ZERO_PAGES))
    return pfns


def _huge_zero_pfn(kernel: Any) -> Optional[int]:
    """``huge_zero_pfn`` (~0 until first use), else the ``huge_zero_page``/``_folio`` pointer."""
    try:
        if kernel.has_symbol("huge_zero_pfn"):
            pfn = int(kernel.object_from_symbol("huge_zero_pfn"))
            return None if pfn in (0, _ENTRY_MASK) else pfn
        for name in ("huge_zero_folio", "huge_zero_page"):
            if kernel.has_symbol(name):
                return _pointer_pfn(kernel, int(kernel.object_from_symbol(name)))
    except exceptions.InvalidAddressException:
        vollog.warning("huge zero page unreadable; huge zero pages unlabelled")
    return None


def _pointer_pfn(kernel: Any, page_address: int) -> Optional[int]:
    if not page_address:
        return None
    from ..linux.secrets.pagecache import make_page_to_phys  # lazy: only without huge_zero_pfn

    to_phys = make_page_to_phys(
        page_object=lambda a: kernel.object("page", offset=a, absolute=True))
    phys = to_phys(page_address)
    return None if phys is None else phys >> PAGE_SHIFT


# --- the classifier -----------------------------------------------------------------------

def classify_frames(members: Mapping[Any, Iterable[Tuple[Any, PageFrame]]],
                    zero_pfns: Iterable[int] = ()) -> FrameClassification:
    """Label every page of every member (see the module docstring for the tiers).

    ``members`` maps a member id (e.g. a pid) to its ``(vma, frame)`` pairs; ``vma`` needs
    ``vm_flags`` and ``file_backed``. Returns the classified pages (member order, then walk
    order) and per-member accounting in bytes.
    """
    walked = {member: list(pairs) for member, pairs in members.items()}
    zero = frozenset(zero_pfns)
    owners, writers = _frame_index(walked, zero)
    pages = []
    for member, pairs in walked.items():
        for vma, frame in pairs:
            pages.append(_classify_page(member, vma, frame, zero, owners, writers))
    return FrameClassification(pages, {m: account(p for p in pages if p.member == m)
                                       for m in walked})


def _frame_index(walked: Dict[Any, List[Tuple[Any, PageFrame]]],
                 zero: frozenset) -> Tuple[Dict[int, Set[Any]], Set[int]]:
    """PFN -> members mapping it; PFNs some member maps writable in a private VMA."""
    owners = collections.defaultdict(set)  # type: Dict[int, Set[Any]]
    writers = set()  # type: Set[int]
    for member, pairs in walked.items():
        for vma, frame in pairs:
            if frame.state != RESIDENT or frame.pfn in zero:
                continue
            owners[frame.pfn].add(member)
            if _is_private(vma) and entry_is_writable(frame.entry):
                writers.add(frame.pfn)
    return owners, writers


def _is_private(vma: Any) -> bool:
    return not (int(getattr(vma, "vm_flags", 0) or 0) & VM_SHARED)


def _classify_page(member: Any, vma: Any, frame: PageFrame, zero: frozenset,
                   owners: Dict[int, Set[Any]], writers: Set[int]) -> ClassifiedPage:
    dirty, writable = entry_is_dirty(frame.entry), entry_is_writable(frame.entry)
    smear = possibly = False
    if frame.state != RESIDENT:
        share_class, decided_by = frame.state, "T0"
    elif frame.pfn in zero:
        share_class, decided_by = ZERO, "special"
    elif not _is_private(vma):
        share_class, decided_by = SHMEM, "T0"
    elif len(owners[frame.pfn]) >= 2:
        share_class, decided_by = _shared_class(vma, dirty, writable), "T1"
        smear = frame.pfn in writers
    else:
        share_class = _private_class(vma, dirty, writable)
        decided_by = "T0" if writable or share_class == SHARED_FILE else "T1"
        possibly = share_class in PRIVATE_CLASSES and not writable
    return ClassifiedPage(member, frame.va, frame.length, frame.pfn, share_class, decided_by,
                          smear, possibly, dirty, writable)


def _shared_class(vma: Any, dirty: bool, writable: bool) -> str:
    if vma.file_backed and not dirty and not writable:
        return SHARED_FILE  # the same page-cache page
    return SHARED_LINEAGE   # a fork-CoW (or KSM) anonymous page


def _private_class(vma: Any, dirty: bool, writable: bool) -> str:
    if not vma.file_backed:
        return PRIVATE_DIRTY if dirty else PRIVATE_CLEAN
    if dirty or writable:
        return PRIVATE_FILE_COW  # a CoW'd copy of a file page (.data/.bss/relro)
    return SHARED_FILE           # clean read-only page of a private file mapping = page cache


def account(pages: Iterable[ClassifiedPage]) -> Dict[str, int]:
    """Post-mortem smaps of one member, in bytes. ``rss`` excludes the zero page (as smaps
    does); ``private_*`` split the private classes by the Dirty bit; ``shared`` is shared
    relative to the group (T1) plus shmem and page-cache file pages."""
    totals = dict.fromkeys(("rss", "private_dirty", "private_clean", "shared", "swapped",
                            "zero", "not_resident", "smear_conflict"), 0)
    for page in pages:
        size = page.length
        if page.share_class in (SWAPPED, NOT_RESIDENT, ZERO):
            totals[page.share_class] += size
            continue
        totals["rss"] += size
        if page.share_class in PRIVATE_CLASSES:
            totals["private_dirty" if page.dirty else "private_clean"] += size
        else:
            totals["shared"] += size
        if page.smear_conflict:
            totals["smear_conflict"] += size
    return totals


def private_ratio(accounting: Mapping[str, int]) -> float:
    """Private bytes / RSS (0.0 for an empty process): the search-space reduction."""
    rss = accounting.get("rss", 0)
    return (accounting.get("private_dirty", 0) + accounting.get("private_clean", 0)) / rss \
        if rss else 0.0


def pages_at(classification: FrameClassification, member: Any,
             vas: Sequence[int]) -> List[Optional[ClassifiedPage]]:
    """The classified page holding each ``va`` of ``member`` (``None`` outside every VMA)."""
    rows = [p for p in classification.pages if p.member == member]
    found = []
    for va in vas:
        found.append(next((p for p in rows if p.va <= va < p.va + p.length), None))
    return found
