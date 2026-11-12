"""``memdiver.page_sharing.PageSharing``: which pages of a process can hold a per-instance secret.

Usage::

    vol -p <vol3plugins> -f image.lime memdiver.page_sharing --comm dropbear --comm sshd --group
    vol -p <vol3plugins> -f image.lime memdiver.page_sharing --pid 11642 11653 --per-vma
    vol -p <vol3plugins> -f image.lime memdiver.page_sharing --comm gocryptfs --dump

A physical frame mapped by two processes has ONE content, so it cannot hold a value that
differs between them. Every resident page of every selected process is walked once (PFN +
raw PTE, :mod:`.frames`) and labelled with a share class:

``private_dirty`` / ``private_clean`` / ``private_file_cow`` -- no other process of the
compared set maps the frame: the candidate set for a per-instance secret.
``shared_lineage`` (fork CoW / KSM), ``shared_file`` (page cache), ``shmem`` (VM_SHARED),
``zero`` (the zero page), ``swapped``, ``not_resident``. Shared frames are labelled, never
dropped: they can hold a *group* secret (a key loaded before ``fork()``).

**Selection matters.** "Shared" is decided over the compared set (tier T1): without
``--global`` a page is private when no OTHER SELECTED process maps its frame. ``--comm sshd``
compares every sshd with every other one; ``--group`` splits the selection into sibling
groups (same main executable) and compares inside each group only; ``--global`` compares
against every process of ``linux.pslist`` (tier T2; ``psscan`` is excluded on purpose: an
exited task's page tables are stale). A process compared with nothing has no T1 evidence:
its pages are private unless T0 (``W=0`` = ``possibly_shared``) says otherwise.

Sibling groups (``--group``): tasks are deduplicated by ``mm`` (threads, vfork) and grouped
by the main executable's identity: the ELF ``NT_GNU_BUILD_ID`` note read through the process
layer from the executable's first mapped page, else the executable path (``vm_file`` of the
VMA holding ``mm.start_code``), else the comm. A pair of members is ``forked`` when their
layout anchors (``start_code``, ``start_brk``, ``start_stack``, ``mmap_base``) are identical
AND they are related by ppid lineage (ancestor or same parent); otherwise ``independent``
(separate ASLR). A group is ``forked``/``independent`` when all its pairs are, else ``mixed``
(``single`` for one member). ``Layout`` names the layout cluster inside the group (``L1`` ...).

Columns are kB except the page counts ``Smear`` (frame seen by >= 2 members while one maps it
writable: acquisition smear, trust neither label), ``PossiblyShared`` (private but W=0) and
``PatchedCode`` (private dirty pages inside a file-backed ``r-x`` mapping: an in-place code
patching indicator). ``Rss`` counts every resident non-zero page, including the PFNMAP
``[vvar]`` page that the kernel's smaps leaves out (+4 kB against ``smaps_rollup``).

``--dump`` writes, per member, ``pagesharing.<pid>.private.dmp`` (its private pages,
concatenated) and one ``pagesharing.json`` with each member's page-class runs and the
``va -> file offset`` map of the dump.

Import rule of this directory: standard library, ``volatility3`` and sibling modules only.
"""
import collections
import json
import logging
import struct
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import frames
from . import process_scope

vollog = logging.getLogger(__name__)

VM_READ, VM_WRITE, VM_EXEC = 0x1, 0x2, 0x4
NT_GNU_BUILD_ID = 3
PT_LOAD, PT_NOTE = 1, 4
BUILD_ID_PREFIX = 16  # hex digits shown in the table
LAYOUT_FIELDS = ("start_code", "start_brk", "start_stack", "mmap_base")

FORKED, INDEPENDENT, MIXED, SINGLE = "forked", "independent", "mixed", "single"

#: One VMA with the facts the classifier (``vm_flags``, ``file_backed``) and the table need.
VmaRecord = collections.namedtuple("VmaRecord", "start end vm_flags file_backed perms name")

#: One process (one address space) of the comparison.
Member = collections.namedtuple(
    "Member", "pid ppid comm layer_name vmas identity build_id exe layout")

COUNTER_COLUMNS = [("RssKB", int), ("PrivateDirtyKB", int), ("PrivateCleanKB", int),
                   ("SharedLineageKB", int), ("SharedFileKB", int), ("ShmemKB", int),
                   ("ZeroKB", int), ("SwappedKB", int), ("PrivatePct", float), ("Smear", int),
                   ("PossiblyShared", int), ("PatchedCode", int)]


# --- pure helpers (unit-tested without an image) -------------------------------------------

def parse_build_id(data: bytes, base: int, read) -> Optional[str]:
    """``NT_GNU_BUILD_ID`` of an ELF64 little-endian image mapped at ``base``.

    ``data`` is the first mapped page (the ELF header); ``read(va, size)`` reads further
    process memory (bytes or ``None``). The load bias is ``base`` minus the page-aligned
    vaddr of the lowest ``PT_LOAD`` (0 for PIE, the link address for ET_EXEC).
    """
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or not phnum or phoff + phentsize * phnum > len(data):
        return None
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize) for i in range(phnum)]
    loads = [h[3] for h in headers if h[0] == PT_LOAD]
    if not loads:
        return None
    bias = base - (min(loads) & ~(frames.PAGE_SIZE - 1))
    for p_type, _flags, _offset, vaddr, _paddr, filesz, _memsz, _align in headers:
        if p_type != PT_NOTE or not filesz:
            continue
        notes = read(bias + vaddr, min(filesz, frames.PAGE_SIZE))
        found = note_build_id(notes or b"")
        if found:
            return found
    return None


def note_build_id(notes: bytes) -> Optional[str]:
    """The ``GNU`` build-id descriptor (hex) of a note segment, if any."""
    pos = 0
    while pos + 12 <= len(notes):
        namesz, descsz, ntype = struct.unpack_from("<III", notes, pos)
        name_at = pos + 12
        desc_at = name_at + ((namesz + 3) & ~3)
        end = desc_at + ((descsz + 3) & ~3)
        if end > len(notes) or namesz > 256 or descsz > 1024:
            return None
        if ntype == NT_GNU_BUILD_ID and notes[name_at:name_at + namesz].rstrip(b"\0") == b"GNU":
            return notes[desc_at:desc_at + descsz].hex() or None
        pos = end
    return None


def is_ancestor(pid: int, other: int, parent_of: Dict[int, int]) -> bool:
    """``pid`` is on ``other``'s ppid chain."""
    seen = set()
    cursor = parent_of.get(other)
    while cursor and cursor not in seen:
        if cursor == pid:
            return True
        seen.add(cursor)
        cursor = parent_of.get(cursor)
    return False


def pair_shape(a: Member, b: Member, parent_of: Dict[int, int]) -> str:
    lineage = (a.ppid == b.ppid or is_ancestor(a.pid, b.pid, parent_of)
               or is_ancestor(b.pid, a.pid, parent_of))
    return FORKED if a.layout == b.layout and lineage else INDEPENDENT


def group_shape(members: Sequence[Member], parent_of: Dict[int, int]) -> str:
    if len(members) < 2:
        return SINGLE
    shapes = set(pair_shape(a, b, parent_of)
                 for i, a in enumerate(members) for b in members[i + 1:])
    return shapes.pop() if len(shapes) == 1 else MIXED


def layout_labels(members: Sequence[Member]) -> Dict[int, str]:
    """``pid -> "L<n>"``: members with identical layout anchors share a label (first seen = L1)."""
    order = {}  # type: Dict[Any, str]
    labels = {}
    for member in members:
        labels[member.pid] = order.setdefault(member.layout, "L%d" % (len(order) + 1))
    return labels


def group_by_identity(members: Sequence[Member]) -> List[List[Member]]:
    """Sibling groups in first-seen order (members keep pslist order)."""
    groups = collections.OrderedDict()  # type: Dict[str, List[Member]]
    for member in members:
        groups.setdefault(member.identity, []).append(member)
    return list(groups.values())


def is_code(vma: Any) -> bool:
    """A file-backed ``r-x`` mapping (executable, not writable)."""
    flags = int(vma.vm_flags)
    return bool(vma.file_backed) and bool(flags & VM_EXEC) and not flags & VM_WRITE


def tally(pairs: Iterable[Tuple[Any, frames.ClassifiedPage]]) -> Dict[str, Any]:
    """Counters of one process or one VMA from ``(vma, classified page)`` pairs."""
    pairs = list(pairs)
    pages = [page for _vma, page in pairs]
    totals = frames.account(pages)
    by_class = collections.Counter()  # type: Dict[str, int]
    for page in pages:
        by_class[page.share_class] += page.length
    return {
        "rss": totals["rss"], "private_dirty": totals["private_dirty"],
        "private_clean": totals["private_clean"],
        "shared_lineage": by_class[frames.SHARED_LINEAGE],
        "shared_file": by_class[frames.SHARED_FILE], "shmem": by_class[frames.SHMEM],
        "zero": totals["zero"], "swapped": totals["swapped"],
        "private_pct": round(100.0 * frames.private_ratio(totals), 2),
        "smear": sum(1 for p in pages if p.smear_conflict),
        "possibly_shared": sum(1 for p in pages if p.possibly_shared),
        "patched_code": sum(1 for vma, p in pairs if p.share_class in frames.PRIVATE_CLASSES
                            and p.dirty and is_code(vma)),
    }


def counter_values(counts: Dict[str, Any]) -> Tuple:
    kb = 1024
    return (counts["rss"] // kb, counts["private_dirty"] // kb, counts["private_clean"] // kb,
            counts["shared_lineage"] // kb, counts["shared_file"] // kb, counts["shmem"] // kb,
            counts["zero"] // kb, counts["swapped"] // kb, float(counts["private_pct"]),
            counts["smear"], counts["possibly_shared"], counts["patched_code"])


def class_runs(pages: Iterable[frames.ClassifiedPage]) -> List[List[Any]]:
    """``[va hex, length, share_class, decided_by, smear, possibly_shared]``, adjacent equal
    pages merged (the ``--dump`` JSON sidecar)."""
    runs = []  # type: List[List[Any]]
    end = None
    for page in pages:
        key = (page.share_class, page.decided_by, page.smear_conflict, page.possibly_shared)
        if runs and end == page.va and tuple(runs[-1][2:]) == key:
            runs[-1][1] += page.length
        else:
            runs.append([page.va, page.length] + list(key))
        end = page.va + page.length
    for run in runs:
        run[0] = hex(run[0])
    return runs


def split_by_member(classification: frames.FrameClassification,
                    walked: Dict[int, List[Tuple[Any, frames.PageFrame]]]
                    ) -> Dict[int, List[Tuple[Any, frames.ClassifiedPage]]]:
    """``classify_frames`` emits pages in member order, then walk order: re-attach the VMAs."""
    out, cursor = {}, 0
    for member, pairs in walked.items():
        pages = classification.pages[cursor:cursor + len(pairs)]
        out[member] = [(vma, page) for (vma, _frame), page in zip(pairs, pages)]
        cursor += len(pairs)
    return out


# --- image access ---------------------------------------------------------------------------

def _int_field(obj: Any, name: str) -> int:
    try:
        return int(getattr(obj, name))
    except Exception:  # vol3 raises InvalidAddressException / AttributeError
        return 0


def task_ppid(task: Any) -> int:
    getter = getattr(task, "get_parent_pid", None)
    for read in ((lambda: getter()) if getter else None,
                 lambda: task.real_parent.tgid, lambda: task.parent.pid):
        if read is None:
            continue
        try:
            return int(read())
        except Exception:  # nosec B112 - fallback chain: vol3 raises InvalidAddressException / AttributeError
            continue
    return 0


def vma_records(context: Any, task: Any) -> List[VmaRecord]:
    mm = task.mm
    brk = (_int_field(mm, "start_brk"), _int_field(mm, "brk"))
    records = []
    for vma in mm.get_vma_iter():
        try:
            start, end, flags = int(vma.vm_start), int(vma.vm_end), int(vma.vm_flags)
        except exceptions.InvalidAddressException:
            continue
        if end <= start:
            continue
        info = frames.vma_info(vma)
        records.append(VmaRecord(start, end, flags, info.file_backed, _perms(vma, flags),
                                 _vma_name(context, task, vma, start, end, brk)))
    return records


def _perms(vma: Any, flags: int) -> str:
    try:
        return str(vma.get_protection())
    except Exception:  # vol3 raises InvalidAddressException / AttributeError
        return "".join(c if flags & bit else "-" for c, bit in
                       (("r", VM_READ), ("w", VM_WRITE), ("x", VM_EXEC)))


def _vma_name(context: Any, task: Any, vma: Any, start: int, end: int, brk) -> str:
    if brk[0] < brk[1] and start < brk[1] and brk[0] < end:
        return "[heap]"
    try:
        return vma.get_name(context, task) or ""
    except Exception:  # a smashed dentry / mount must not kill the row
        return "?"


def _vm_file(vma: Any) -> int:
    try:
        return int(vma.vm_file)
    except Exception:  # vol3 raises InvalidAddressException / AttributeError
        return 0


class PageCacheReader(object):
    """Reads page ``index`` of a file through the kernel page cache (``vm_file->f_mapping``).

    A forked child has no PTEs for file pages it never touched (``fork()`` does not copy
    them), so the exe's first page is often absent from its process layer while the page
    cache still holds it.
    """

    KEYS = (("address_space.i_pages", "address_space", "i_pages"),
            ("xarray.xa_head", "xarray", "xa_head"), ("xa_node.shift", "xa_node", "shift"),
            ("xa_node.slots", "xa_node", "slots"), ("page.mapping", "page", "mapping"))

    def __init__(self, context: Any, kernel_name: str) -> None:
        from ..linux import kernel_common
        from ..linux.secrets import pagecache

        self._pagecache = pagecache
        vmlinux, kernel_layer, self._reader = kernel_common.kernel_reader(context, kernel_name)
        self._layout = {}  # type: Dict[str, int]
        for key, type_name, member in self.KEYS:
            offset = kernel_common.isf_offset(vmlinux, type_name, member)
            if offset is not None:
                self._layout[key] = offset
        self._to_phys = pagecache.make_page_to_phys(
            page_object=lambda a: vmlinux.object("page", offset=a, absolute=True))
        self._physical = context.layers[kernel_layer.config["memory_layer"]]

    def read(self, mapping: int, index: int) -> Optional[bytes]:
        try:
            phys = self._pagecache.mapping_page(self._reader, self._layout, mapping, index,
                                                self._to_phys)
            return None if phys is None else self._physical.read(phys, frames.PAGE_SIZE)
        except exceptions.InvalidAddressException:
            return None


def _f_mapping(vma: Any) -> int:
    try:
        return int(vma.vm_file.dereference().f_mapping)
    except Exception:  # vol3 raises InvalidAddressException / AttributeError
        return 0


def exe_identity(context: Any, task: Any, layer: Any,
                 page_cache: Optional[PageCacheReader] = None
                 ) -> Tuple[Optional[str], Optional[str]]:
    """``(build_id, exe path)`` of the task's main executable (either may be ``None``).

    The ELF header and notes are read through the process layer, falling back to the
    executable's page cache (``page_cache``) for pages the process never faulted in."""
    start_code = _int_field(task.mm, "start_code")
    vmas = list(task.mm.get_vma_iter())
    holder = next((v for v in vmas if int(v.vm_start) <= start_code < int(v.vm_end)), None)
    file_ptr = _vm_file(holder) if holder is not None else 0
    if not file_ptr:
        return None, None
    try:
        exe = holder.get_name(context, task) or None
    except Exception:  # unresolvable path: identity falls back to the build-id or comm
        exe = None
    mapped = sorted((int(v.vm_start), _int_field(v, "vm_pgoff"))
                    for v in vmas if _vm_file(v) == file_ptr)
    base = next((start for start, pgoff in mapped if pgoff == 0), mapped[0][0])

    mapping = _f_mapping(holder) if page_cache is not None else 0

    def read(va, size):
        try:
            return layer.read(va, size)
        except exceptions.InvalidAddressException:
            pass
        if not mapping or va < base:  # page cache: file offset = va - base (first segment)
            return None
        first, last = (va - base) >> frames.PAGE_SHIFT, (va - base + size - 1) >> frames.PAGE_SHIFT
        pages = [page_cache.read(mapping, index) for index in range(first, last + 1)]
        if any(page is None for page in pages):
            return None
        start = (va - base) & (frames.PAGE_SIZE - 1)
        return b"".join(pages)[start:start + size]

    header = read(base, frames.PAGE_SIZE)
    return (parse_build_id(header, base, read) if header else None), exe


def make_member(context: Any, task: Any,
                page_cache: Optional[PageCacheReader] = None) -> Optional[Member]:
    try:
        layer_name = task.add_process_layer()
    except exceptions.InvalidAddressException:
        return None
    if not layer_name:
        return None
    pid, name = int(task.pid), process_scope.comm(task)
    try:
        build_id, exe = exe_identity(context, task, context.layers[layer_name], page_cache)
    except exceptions.InvalidAddressException:
        build_id, exe = None, None
    identity = ("build-id:" + build_id) if build_id else ("exe:" + exe) if exe else \
        ("comm:" + name)
    layout = tuple(_int_field(task.mm, f) for f in LAYOUT_FIELDS)
    return Member(pid, task_ppid(task), name, layer_name, vma_records(context, task), identity,
                  build_id, exe, layout)


def walk(context: Any, member: Member) -> List[Tuple[Any, frames.PageFrame]]:
    began = time.time()
    pairs = list(frames.member_frames(context.layers[member.layer_name], member.vmas))
    vollog.info("memdiver.page_sharing: pid %d walked %d VMAs, %d records in %.2f s",
                member.pid, len(member.vmas), len(pairs), time.time() - began)
    return pairs


# --- the plugin ----------------------------------------------------------------------------

class PageSharing(interfaces.plugins.PluginInterface):
    """Labels every page of the selected processes private / shared by physical frame."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(
                name="pid", element_type=int, optional=True,
                description="Process IDs to compare (default: every process with an mm)"),
            process_scope.comm_requirement(),
            requirements.BooleanRequirement(
                name="group", optional=True, default=False,
                description="Split the selection into sibling groups (same main executable) "
                            "and decide sharing inside each group"),
            requirements.BooleanRequirement(
                name="per_vma", optional=True, default=False,
                description="One row per VMA instead of one per process"),
            requirements.BooleanRequirement(
                name="global", optional=True, default=False,
                description="Decide 'shared' against every pslist process (T2), not only "
                            "the selection"),
            requirements.BooleanRequirement(
                name="dump", optional=True, default=False,
                description="Write each member's private pages + pagesharing.json"),
        ]

    # ------------------------------------------------------------------ analysis

    def _members(self, tasks) -> List[Member]:
        if not hasattr(self, "_page_cache"):
            try:
                self._page_cache = PageCacheReader(self.context, self.config["kernel"])
            except Exception as err:  # no usable page-cache layout: process layer only
                vollog.info("memdiver.page_sharing: page-cache fallback off: %s", err)
                self._page_cache = None
        members = []
        for task in tasks:
            member = make_member(self.context, task, self._page_cache)
            if member is not None:
                members.append(member)
        return members

    def _analyse(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]
        everyone = process_scope.selected_tasks(self.context, kernel_name)
        parent_of = {int(t.pid): task_ppid(t) for t in everyone}
        wanted = process_scope.selected_tasks(self.context, kernel_name,
                                              self.config.get("pid", None),
                                              self.config.get("comm", None))
        wanted, dropped = process_scope.dedup_by_mm(wanted)
        for pid, kept in sorted(dropped.items()):
            vollog.info("memdiver.page_sharing: pid %d shares the mm of pid %d; skipped", pid, kept)
        members = self._members(wanted)
        groups = group_by_identity(members) if self.config.get("group") else [members]
        zero = frames.zero_page_pfns(self.context, kernel)
        walked = collections.OrderedDict((m.pid, walk(self.context, m)) for m in members)
        if self.config.get("global"):
            others, _ = process_scope.dedup_by_mm(
                [t for t in everyone if int(t.pid) not in walked])
            mms = set()
            for task in wanted:
                mms.add(int(task.mm))
            compare = collections.OrderedDict(walked)
            for member in self._members(t for t in others if int(t.mm) not in mms):
                compare[member.pid] = walk(self.context, member)
            labelled = split_by_member(frames.classify_frames(compare, zero), compare)
        else:
            labelled = {}
            for group in groups:
                part = collections.OrderedDict((m.pid, walked[m.pid]) for m in group)
                labelled.update(split_by_member(frames.classify_frames(part, zero), part))
        return [(index + 1, group, group_shape(group, parent_of), layout_labels(group))
                for index, group in enumerate(groups) if group], labelled

    # ------------------------------------------------------------------ output

    def _dump(self, groups, labelled) -> None:
        document = []
        for number, group, shape, layouts in groups:
            for member in group:
                document.append(self._dump_member(number, shape, member, labelled[member.pid]))
        process_scope.write_text(self, "pagesharing.json",
                                 json.dumps(document, indent=1, sort_keys=True))

    def _dump_member(self, number, shape, member, pairs) -> Dict[str, Any]:
        layer = self.context.layers[member.layer_name]
        name = "pagesharing.%d.private.dmp" % member.pid
        offsets = []  # type: List[List[Any]]
        offset = 0
        with self.open(name) as handle:
            for _vma, page in pairs:
                if page.share_class not in frames.PRIVATE_CLASSES:
                    continue
                handle.write(layer.read(page.va, page.length, pad=True))
                if offsets and offsets[-1][3] == page.va:
                    offsets[-1][1] += page.length
                    offsets[-1][3] += page.length
                else:
                    offsets.append([page.va, page.length, offset, page.va + page.length])
                offset += page.length
        return {"group": number, "shape": shape, "pid": member.pid, "ppid": member.ppid,
                "comm": member.comm, "identity": member.identity, "build_id": member.build_id,
                "exe": member.exe, "private_file": name,
                "private_runs": [[hex(va), size, at] for va, size, at, _end in offsets],
                "classes": class_runs(page for _vma, page in pairs),
                "counts": tally(pairs)}

    def _process_rows(self, groups, labelled):
        for number, group, shape, layouts in groups:
            for member in group:
                yield 0, (number, shape, layouts[member.pid], member.pid, member.ppid,
                          member.comm or "-", _short_identity(member)) + \
                    counter_values(tally(labelled[member.pid]))

    def _vma_rows(self, groups, labelled):
        for number, _group, _shape, _layouts in groups:
            for member in _group:
                by_vma = collections.OrderedDict()  # type: Dict[Any, List[Any]]
                for vma, page in labelled[member.pid]:
                    by_vma.setdefault((vma.start, vma.end), []).append((vma, page))
                for vma in member.vmas:
                    yield 0, (number, member.pid, member.comm or "-", format_hints.Hex(vma.start),
                              format_hints.Hex(vma.end), vma.perms, vma.name or "-") + \
                        counter_values(tally(by_vma.get((vma.start, vma.end), [])))

    def run(self):
        groups, labelled = self._analyse()
        if self.config.get("dump"):
            self._dump(groups, labelled)
        if self.config.get("per_vma"):
            columns = [("Group", int), ("PID", int), ("COMM", str), ("Start", format_hints.Hex),
                       ("End", format_hints.Hex), ("Perms", str), ("Name", str)]
            return renderers.TreeGrid(columns + COUNTER_COLUMNS, self._vma_rows(groups, labelled))
        columns = [("Group", int), ("Shape", str), ("Layout", str), ("PID", int), ("PPID", int),
                   ("COMM", str), ("BuildId", str)]
        return renderers.TreeGrid(columns + COUNTER_COLUMNS, self._process_rows(groups, labelled))


def _short_identity(member: Member) -> str:
    if member.build_id:
        return member.build_id[:BUILD_ID_PREFIX]
    return member.identity
