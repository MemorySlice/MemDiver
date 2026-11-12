"""Page-cache lookups: which physical page holds index ``i`` of an ``address_space``.

``struct address_space.i_pages`` is an XArray (lib/xarray.c, include/linux/xarray.h, v4.20+).
Entry encoding (``XA_CHUNK_SHIFT`` 6, 64 slots per ``struct xa_node``)::

    entry & 3 == 2, entry > 4096   internal: pointer to an xa_node, ``node = entry - 2``
    entry & 3 == 2, entry >> 2 < 63 sibling (CONFIG_XARRAY_MULTI): this slot belongs to the
                                    multi-index entry in slot ``entry >> 2`` of the same node
    other internal values          retry / zero entries: nothing stored
    entry & 1                       value entry: a swap or shadow (workingset) entry, i.e.
                                    the page is NOT resident
    otherwise                       a ``struct page *`` (the head page of a folio)

A lookup (``xas_descend``) starts at ``xa_head`` (when that is not a node it is the entry
for index 0 alone); in a node with ``shift`` it takes slot ``(index >> shift) & 63``,
follows a sibling to its canonical slot and descends.  A page entry found in slot ``c`` of
a node is a folio whose first index is ``node_base + (c << shift)``; the folio's pages are
physically contiguous, so index ``i`` is at ``phys(folio) + ((i - folio_index) << 12)``.

A slot can be STALE in a live acquisition: the page was freed and reused by another file
while the tree still points at it (seen on a real image: 114 slots of a 64 MiB file whose
pages carry another inode's ``mapping`` and ``index``).  So by default a page entry is only
accepted when its ``page->mapping`` is this ``address_space`` (``check_mapping=True``).

The reader is duck-typed like ``kernel_common.SafeReader``: ``reader.ptr(addr)`` and
``reader.u8(addr)`` return an int or None.  ``kl`` is any mapping ``"type.member" ->
offset`` (an ``IsfLayout``); missing keys fall back to ``PAGECACHE_DEFAULTS`` (LP64, v6.8).

Self-contained: standard library only, paste-safe (no relative import, no ``__file__``),
Python 3.8.
"""

from typing import Any, Callable, Iterator, Optional, Tuple

PAGE_SHIFT = 12
PAGECACHE_DEFAULTS = {  # LP64 v6.8 (include/linux/fs.h, xarray.h, mm_types.h)
    "address_space.i_pages": 8,
    "xarray.xa_head": 8,
    "xa_node.shift": 0,
    "xa_node.slots": 40,
    "sizeof(page)": 64,
    "page.mapping": 24,
}
_PC_CHUNK_SHIFT = 6
_PC_CHUNK_SIZE = 1 << _PC_CHUNK_SHIFT
_PC_MAX_DEPTH = 11  # ceil(64 / 6): an unsigned long index never needs more levels
_PC_INDEX_MASK = (1 << 64) - 1


def _pc_off(kl: Any, key: str) -> int:
    try:
        return int(kl[key])
    except (KeyError, TypeError, IndexError):
        return PAGECACHE_DEFAULTS[key]


def _pc_is_internal(entry: int) -> bool:
    return entry & 3 == 2


def _pc_is_node(entry: int) -> bool:
    return _pc_is_internal(entry) and entry > 4096


def _pc_is_sibling(entry: int) -> bool:
    return _pc_is_internal(entry) and (entry >> 2) < _PC_CHUNK_SIZE - 1


def _pc_is_page(entry: Optional[int]) -> bool:
    """A non-NULL, non-value, non-internal entry: a ``struct page *``."""
    return bool(entry) and not entry & 1 and not _pc_is_internal(entry)


class _PcNodes:
    """Reads of ``struct xa_node`` fields through the duck-typed reader."""

    def __init__(self, reader: Any, kl: Any) -> None:
        self.reader = reader
        self.shift_off = _pc_off(kl, "xa_node.shift")
        self.slots_off = _pc_off(kl, "xa_node.slots")
        self.pointer_size = int(getattr(reader, "pointer_size", 8) or 8)

    def shift(self, node: int) -> Optional[int]:
        shift = self.reader.u8(node + self.shift_off)
        if shift is None or shift % _PC_CHUNK_SHIFT or shift >= 64:
            return None
        return shift

    def slot(self, node: int, offset: int) -> Optional[int]:
        return self.reader.ptr(node + self.slots_off + offset * self.pointer_size)


def _pc_head(reader: Any, kl: Any, mapping: int) -> Optional[int]:
    return reader.ptr(mapping + _pc_off(kl, "address_space.i_pages") + _pc_off(kl, "xarray.xa_head"))


def _pc_lookup(nodes: _PcNodes, head: int, index: int) -> Optional[Tuple[int, int]]:
    """``(page entry, folio first index)`` for ``index`` below the node ``head``, else None."""
    node, expected = head - 2, None
    for _ in range(_PC_MAX_DEPTH):
        shift = nodes.shift(node)
        if shift is None or (expected is not None and shift != expected):
            return None
        if expected is None and shift + _PC_CHUNK_SHIFT < 64 and index >> (shift + _PC_CHUNK_SHIFT):
            return None  # beyond what the root node spans
        offset = (index >> shift) & (_PC_CHUNK_SIZE - 1)
        entry = nodes.slot(node, offset)
        if entry is not None and _pc_is_sibling(entry):
            offset = entry >> 2
            entry = nodes.slot(node, offset)
        if entry is None:
            return None
        if _pc_is_node(entry) and not shift:
            return None  # a leaf node cannot have children
        if _pc_is_node(entry):
            node, expected = entry - 2, shift - _PC_CHUNK_SHIFT
            continue
        if not _pc_is_page(entry):
            return None
        span_mask = (_PC_CHUNK_SIZE << shift) - 1 if shift + _PC_CHUNK_SHIFT < 64 else _PC_INDEX_MASK
        return entry, (index & ~span_mask & _PC_INDEX_MASK) | (offset << shift)
    return None


def canonical_address(address: int) -> int:
    """Sign-extend an x86-64 kernel address that vol3 masked to 48 (or LA57: 57) bits.

    ``int()`` of a vol3 pointer object is masked to the layer's address width (``0x8d36...``)
    while a raw 8-byte read gives the canonical form (``0xffff8d36...``); compare canonically.
    """
    for bits in (57, 48):
        if address >> (bits - 1) == 1:
            return address | (((1 << 64) - 1) ^ ((1 << bits) - 1))
    return address


def _pc_owned(reader: Any, kl: Any, mapping: int, page: int, check_mapping: bool) -> bool:
    """``page->mapping == mapping`` (a stale slot points at a page reused by another file)."""
    if not check_mapping:
        return True
    owner = reader.ptr(page + _pc_off(kl, "page.mapping"))
    return owner is not None and canonical_address(owner) == canonical_address(mapping)


def mapping_page(reader: Any, kl: Any, mapping: int, index: int,
                 page_to_phys: Callable[[int], Optional[int]],
                 check_mapping: bool = True) -> Optional[int]:
    """Physical address of page ``index`` of the ``address_space`` at ``mapping``, else None.

    None means not resident (no entry, a swap/shadow value entry), a stale slot (the page's
    ``mapping`` is another file; skipped unless ``check_mapping=False``) or unreadable.
    ``page_to_phys`` maps a ``struct page *`` to its physical address (``make_page_to_phys``).
    """
    if index < 0 or index > _PC_INDEX_MASK:
        return None
    head = _pc_head(reader, kl, mapping)
    if not head:
        return None
    if not _pc_is_node(head):
        found = (head, 0) if index == 0 and _pc_is_page(head) else None
    else:
        found = _pc_lookup(_PcNodes(reader, kl), head, index)
    if found is None or not _pc_owned(reader, kl, mapping, found[0], check_mapping):
        return None
    phys = page_to_phys(found[0])
    return None if phys is None else phys + ((index - found[1]) << PAGE_SHIFT)


def _pc_sibling_run(nodes: _PcNodes, node: int, offset: int) -> int:
    """How many slots after ``offset`` are siblings of it (a multi-index entry's tail)."""
    run = 0
    while offset + run + 1 < _PC_CHUNK_SIZE:
        entry = nodes.slot(node, offset + run + 1)
        if entry is None or not _pc_is_sibling(entry) or entry >> 2 != offset:
            break
        run += 1
    return run


def _pc_walk(nodes: _PcNodes, node: int, base: int, expected: Optional[int],
             depth: int) -> Iterator[Tuple[int, int, int]]:
    """Yield ``(first index, page entry, number of indexes)`` for every page entry, in order."""
    shift = nodes.shift(node)
    if depth > _PC_MAX_DEPTH or shift is None or (expected is not None and shift != expected):
        return
    for offset in range(_PC_CHUNK_SIZE):
        entry = nodes.slot(node, offset)
        if not entry or _pc_is_sibling(entry):
            continue
        start = base + (offset << shift)
        if _pc_is_node(entry):
            if shift:
                yield from _pc_walk(nodes, entry - 2, start, shift - _PC_CHUNK_SHIFT, depth + 1)
        elif _pc_is_page(entry):
            yield start, entry, (1 + _pc_sibling_run(nodes, node, offset)) << shift


def iter_mapping_pages(reader: Any, kl: Any, mapping: int, limit: int = 1 << 20,
                       page_to_phys: Optional[Callable[[int], Optional[int]]] = None,
                       check_mapping: bool = True) -> Iterator[Tuple[int, int]]:
    """Yield ``(index, page)`` for at most ``limit`` resident pages, in index order.

    ``page`` is the physical address when ``page_to_phys`` is given, else the address of the
    page's ``struct page`` (``folio + k * sizeof(page)`` inside a large folio).  Value
    (swap/shadow) entries are skipped: they are not resident; so are stale slots (see
    ``mapping_page``).
    """
    head = _pc_head(reader, kl, mapping)
    if not head or limit <= 0:
        return
    if _pc_is_node(head):
        entries = _pc_walk(_PcNodes(reader, kl), head - 2, 0, None, 0)
    else:
        entries = iter([(0, head, 1)] if _pc_is_page(head) else [])
    sizeof_page, count = _pc_off(kl, "sizeof(page)"), 0
    for first, entry, span in entries:
        if not _pc_owned(reader, kl, mapping, entry, check_mapping):
            continue
        phys = page_to_phys(entry) if page_to_phys is not None else None
        if page_to_phys is not None and phys is None:
            continue
        for k in range(span):
            yield first + k, (phys + (k << PAGE_SHIFT)) if phys is not None else entry + k * sizeof_page
            count += 1
            if count >= limit:
                return


def page_to_phys(page: Any, vmemmap_base: Optional[int] = None, sizeof_page: int = 64) -> Optional[int]:
    """Physical address of a ``struct page``: vol3's ``page.to_paddr()`` when the object has it,
    else ``(page - vmemmap_base) // sizeof(page) << 12`` (SPARSEMEM_VMEMMAP)."""
    if hasattr(page, "to_paddr"):
        try:
            return int(page.to_paddr())
        except Exception:  # vol3 raises LayerException / InvalidAddressException
            return None
    address = int(page)
    if vmemmap_base is None or address < vmemmap_base or sizeof_page <= 0:
        return None
    return ((address - vmemmap_base) // sizeof_page) << PAGE_SHIFT


def make_page_to_phys(vmemmap_base: Optional[int] = None, sizeof_page: int = 64,
                      page_object: Optional[Callable[[int], Any]] = None) -> Callable[[int], Optional[int]]:
    """A ``page_to_phys`` callable for ``mapping_page`` / ``iter_mapping_pages``.

    ``page_object(address)`` (e.g. ``lambda a: vmlinux.object("page", offset=a,
    absolute=True)``) is preferred so vol3's own ``to_paddr()`` decides; otherwise the
    vmemmap arithmetic with ``vmemmap_base`` is used.
    """
    def convert(address: int) -> Optional[int]:
        if page_object is not None:
            try:
                obj = page_object(address)
            except Exception:  # an unreadable page object: fall back to arithmetic
                obj = None
            if obj is not None and hasattr(obj, "to_paddr"):
                return page_to_phys(obj)
        return page_to_phys(address, vmemmap_base, sizeof_page)
    return convert
