"""Sibling groups: several instances of one program inside ONE full memory image (plan S2).

A single image often holds several processes of the same binary (dropbear/sshd sessions,
gocryptfs mounts, forked workers). They can stand in for the N captures of the
differential. This module finds them; :mod:`memdiver.core.image.page_sharing` then
classifies their frames (T1 within the group).

* **Address-space dedup:** tasks sharing an ``mm`` are ONE member (threads, vfork/CLONE_VM
  children). The first pid in task-list order wins.
* **Identity:** the ELF build-id (``NT_GNU_BUILD_ID``) read through the process layer from
  the main executable's first mapped page (the VMA with the same ``vm_file`` as the VMA
  holding ``mm.start_code`` and ``vm_pgoff == 0``). Fallbacks, in order: the executable's
  path (name of the ``start_code`` VMA), then ``comm``. A member whose build-id page is not
  resident inherits the build-id another member with the same executable path proved. The
  inode is never used (overlayfs gives every container its own inode for one binary).
* **ASLR signature:** ``(start_code, mmap_base, start_stack)`` of the ``mm``. ``fork()``
  copies all three; a fresh ``execve()`` re-randomises them.
* **Shape** per member pair: ``forked`` (same ASLR signature AND ppid lineage: one is the
  other's ancestor, or they share a parent), ``independent`` (signatures differ = separate
  ASLR), ``same_layout_unrelated`` (same signature, no lineage: suspicious). Group shape is
  ``forked``/``independent`` when every analysed pair agrees, else ``mixed``.
* **Families:** one identity can run as several unrelated process trees (two dropbear
  listeners, each with sessions). With ``split_families`` (default) each lineage tree
  (members connected by ppid) is its own group, and the instances with no relative in the
  identity (independent daemons) are pooled into one group (``family_root = None``).
* **Role hints** from the lineage inside the group: ``listener`` (has member children, its
  parent is not a member), ``intermediate`` (has member children and a member parent, e.g. an
  OpenSSH privsep monitor), ``child``, ``standalone``. The listener is listed but excluded
  from the analysis set unless ``include_parent``.

Pure grouping (:func:`group_siblings`) is separated from the vol3 walk
(:func:`collect_task_facts`) so it can be tested without an image.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from memdiver.core.image.context import ImageContext

PAGE_SIZE = 4096
#: Bytes of a PT_NOTE segment read at most (build-id notes are tiny).
NOTE_READ_LIMIT = 4096
PT_NOTE = 4
NT_GNU_BUILD_ID = 3

ROLE_LISTENER = "listener"
ROLE_INTERMEDIATE = "intermediate"
ROLE_CHILD = "child"
ROLE_STANDALONE = "standalone"

SHAPE_FORKED = "forked"
SHAPE_INDEPENDENT = "independent"
SHAPE_MIXED = "mixed"
SHAPE_SINGLE = "single"
PAIR_SAME_LAYOUT_UNRELATED = "same_layout_unrelated"

#: ELF class -> (phdr field formats, offsets) for e_phoff/e_phentsize/e_phnum and p_* fields.
_ELF_LAYOUT = {
    1: {"phoff": (0x1C, "I"), "phentsize": (0x2A, "H"), "phnum": (0x2C, "H"),
        "p_type": (0, "I"), "p_offset": (4, "I"), "p_filesz": (16, "I")},
    2: {"phoff": (0x20, "Q"), "phentsize": (0x36, "H"), "phnum": (0x38, "H"),
        "p_type": (0, "I"), "p_offset": (8, "Q"), "p_filesz": (32, "Q")},
}

#: Reads ``length`` bytes at a process VA; raises on an unreadable address.
Reader = Callable[[int, int], bytes]


@dataclass(frozen=True)
class TaskFacts:
    """What grouping needs to know about one address space."""

    pid: int
    ppid: int
    comm: str
    mm: int
    aslr: Tuple[int, int, int]           # (start_code, mmap_base, start_stack)
    exe_path: Optional[str] = None
    build_id: Optional[str] = None
    build_id_source: Optional[str] = None  # "elf_note" | "inferred_from_exe" | None
    build_id_error: Optional[str] = None

    @property
    def identity(self) -> Tuple[str, str]:
        if self.build_id:
            return "build_id", self.build_id
        if self.exe_path:
            return "exe_path", self.exe_path
        return "comm", self.comm


@dataclass(frozen=True)
class SiblingMember:
    facts: TaskFacts
    role: str
    analysed: bool


@dataclass
class SiblingGroup:
    identity_kind: str
    identity: str
    #: pid of the lineage root (``None``: the pooled standalone instances of the identity).
    family_root: Optional[int]
    members: List[SiblingMember]
    shape: str
    pair_shapes: Dict[str, int]
    #: pids per distinct ASLR signature (one cluster per independently exec'd image).
    layout_clusters: List[List[int]]

    @property
    def analysis_pids(self) -> List[int]:
        return [m.facts.pid for m in self.members if m.analysed]


@dataclass
class SiblingDiscovery:
    groups: List[SiblingGroup]
    tasks_examined: int
    #: pid -> the pid whose ``mm`` it shares (dropped from grouping).
    same_address_space: Dict[int, int] = field(default_factory=dict)
    seconds: float = 0.0


# --- ELF build-id ---------------------------------------------------------------------------

def parse_build_id(read: Reader, base: int, mapped_len: int) -> Optional[str]:
    """The GNU build-id of the ELF image whose file offset 0 is mapped at ``base``.

    Only PT_NOTE segments that lie inside the first ``mapped_len`` bytes are read (they are
    in the first page on every common toolchain). ``None`` when the header is not ELF or no
    build-id note is found; a read error propagates.
    """
    header = read(base, 64)
    if header[:4] != b"\x7fELF" or header[4] not in _ELF_LAYOUT or header[5] not in (1, 2):
        return None
    layout = _ELF_LAYOUT[header[4]]
    endian = "<" if header[5] == 1 else ">"

    def field_of(blob: bytes, name: str, at: int = 0) -> int:
        offset, fmt = layout[name]
        return int(struct.unpack_from(endian + fmt, blob, at + offset)[0])

    phoff, phentsize, phnum = (field_of(header, k) for k in ("phoff", "phentsize", "phnum"))
    if not phnum or phoff + phentsize * phnum > mapped_len:
        return None
    table = read(base + phoff, phentsize * phnum)
    for index in range(phnum):
        at = index * phentsize
        if field_of(table, "p_type", at) != PT_NOTE:
            continue
        offset, size = field_of(table, "p_offset", at), field_of(table, "p_filesz", at)
        size = min(size, NOTE_READ_LIMIT, max(0, mapped_len - offset))
        if size <= 0:
            continue
        found = _gnu_build_id(read(base + offset, size), endian)
        if found:
            return found
    return None


def _gnu_build_id(notes: bytes, endian: str) -> Optional[str]:
    """Walk a note segment for ``NT_GNU_BUILD_ID`` with owner ``GNU``."""
    cursor = 0
    while cursor + 12 <= len(notes):
        namesz, descsz, kind = struct.unpack_from(endian + "III", notes, cursor)
        name_at = cursor + 12
        desc_at = name_at + _align4(namesz)
        end = desc_at + _align4(descsz)
        if end > len(notes) or namesz > len(notes):
            return None
        if kind == NT_GNU_BUILD_ID and notes[name_at:name_at + namesz] == b"GNU\x00" and descsz:
            return notes[desc_at:desc_at + descsz].hex()
        cursor = end
    return None


def _align4(value: int) -> int:
    return (value + 3) & ~3


# --- pure grouping -------------------------------------------------------------------------

def fill_build_ids_from_exe(facts: Sequence[TaskFacts]) -> List[TaskFacts]:
    """A member without a readable build-id inherits the one its executable path proved.

    Only when exactly one build-id is known for that path (an upgraded binary on disk
    would otherwise merge two builds).
    """
    by_path: Dict[str, set] = {}
    for item in facts:
        if item.build_id and item.exe_path:
            by_path.setdefault(item.exe_path, set()).add(item.build_id)
    out = []
    for item in facts:
        known = by_path.get(item.exe_path or "", set())
        if not item.build_id and len(known) == 1:
            item = TaskFacts(item.pid, item.ppid, item.comm, item.mm, item.aslr, item.exe_path,
                             next(iter(known)), "inferred_from_exe", item.build_id_error)
        out.append(item)
    return out


def _is_ancestor(ancestor: int, pid: int, parents: Mapping[int, int]) -> bool:
    seen = set()
    current = parents.get(pid)
    while current is not None and current not in seen and current > 0:
        if current == ancestor:
            return True
        seen.add(current)
        current = parents.get(current)
    return False


def pair_shape(a: TaskFacts, b: TaskFacts, parents: Mapping[int, int]) -> str:
    """``forked`` | ``independent`` | ``same_layout_unrelated`` for one member pair."""
    if a.aslr != b.aslr:
        return SHAPE_INDEPENDENT
    related = (a.ppid == b.ppid or _is_ancestor(a.pid, b.pid, parents)
               or _is_ancestor(b.pid, a.pid, parents))
    return SHAPE_FORKED if related else PAIR_SAME_LAYOUT_UNRELATED


def member_roles(facts: Sequence[TaskFacts]) -> Dict[int, str]:
    """Role hint of every member from the ppid lineage INSIDE the group."""
    pids = {f.pid for f in facts}
    with_children = {f.ppid for f in facts if f.ppid in pids}
    roles = {}
    for item in facts:
        has_children, has_parent = item.pid in with_children, item.ppid in pids
        if has_children:
            roles[item.pid] = ROLE_INTERMEDIATE if has_parent else ROLE_LISTENER
        else:
            roles[item.pid] = ROLE_CHILD if has_parent else ROLE_STANDALONE
    return roles


def group_shape(facts: Sequence[TaskFacts],
                parents: Mapping[int, int]) -> Tuple[str, Dict[str, int]]:
    """(group shape, count per pair shape) over every pair of ``facts``."""
    counts: Dict[str, int] = {}
    for i, a in enumerate(facts):
        for b in facts[i + 1:]:
            kind = pair_shape(a, b, parents)
            counts[kind] = counts.get(kind, 0) + 1
    if not counts:
        return SHAPE_SINGLE, counts
    if set(counts) == {SHAPE_FORKED}:
        return SHAPE_FORKED, counts
    if set(counts) == {SHAPE_INDEPENDENT}:
        return SHAPE_INDEPENDENT, counts
    return SHAPE_MIXED, counts


def _layout_clusters(facts: Sequence[TaskFacts]) -> List[List[int]]:
    clusters: Dict[Tuple[int, int, int], List[int]] = {}
    for item in facts:
        clusters.setdefault(item.aslr, []).append(item.pid)
    return list(clusters.values())


def lineage_families(facts: Sequence[TaskFacts]) -> List[Tuple[Optional[int], List[TaskFacts]]]:
    """Split one identity's members into lineage trees (root pid, members); members without
    any relative are pooled under root ``None``."""
    by_pid = {f.pid: f for f in facts}

    def root_of(item: TaskFacts) -> int:
        seen = {item.pid}
        while item.ppid in by_pid and item.ppid not in seen:
            item = by_pid[item.ppid]
            seen.add(item.pid)
        return item.pid

    trees: Dict[int, List[TaskFacts]] = {}
    for item in facts:
        trees.setdefault(root_of(item), []).append(item)
    pooled = [t[0] for t in trees.values() if len(t) == 1]
    families: List[Tuple[Optional[int], List[TaskFacts]]] = [
        (root, members) for root, members in trees.items() if len(members) > 1]
    if pooled:
        families.append((None, pooled))
    return families


def _build_group(kind: str, identity: str, root: Optional[int], facts: List[TaskFacts],
                 parents: Mapping[int, int], include_parent: bool) -> SiblingGroup:
    roles = member_roles(facts)
    members = [SiblingMember(f, roles[f.pid], include_parent or roles[f.pid] != ROLE_LISTENER)
               for f in facts]
    analysed = [m.facts for m in members if m.analysed]
    shape, pairs = group_shape(analysed, parents)
    return SiblingGroup(kind, identity, root, members, shape, pairs, _layout_clusters(analysed))


def group_siblings(facts: Iterable[TaskFacts], parents: Mapping[int, int], *,
                   min_members: int = 2, include_parent: bool = False,
                   split_families: bool = True) -> List[SiblingGroup]:
    """Group address spaces by identity (and lineage family); keep groups with
    >= ``min_members`` ANALYSED members.

    ``parents`` is the pid -> ppid map of the whole task list (lineage may run through
    tasks outside the group). Groups come largest first, then by identity and root.
    """
    by_identity: Dict[Tuple[str, str], List[TaskFacts]] = {}
    for item in fill_build_ids_from_exe(list(facts)):
        by_identity.setdefault(item.identity, []).append(item)
    groups: List[SiblingGroup] = []
    for (kind, ident), items in by_identity.items():
        items = sorted(items, key=lambda f: f.pid)
        families = lineage_families(items) if split_families else [(None, items)]
        groups.extend(_build_group(kind, ident, root, members, parents, include_parent)
                      for root, members in families)
    kept = [g for g in groups if len(g.analysis_pids) >= max(1, min_members)]
    return sorted(kept, key=lambda g: (-len(g.members), g.identity, g.family_root or 0))


# --- the vol3 walk -------------------------------------------------------------------------

def discover_siblings(image_ctx: ImageContext, *, comm: Optional[str] = None,
                      min_members: int = 2, include_parent: bool = False,
                      split_families: bool = True) -> SiblingDiscovery:
    """Find the sibling groups of one image (see the module docstring)."""
    started = time.perf_counter()
    facts, parents, duplicates = collect_task_facts(image_ctx, comm=comm)
    groups = group_siblings(facts, parents, min_members=min_members,
                            include_parent=include_parent, split_families=split_families)
    return SiblingDiscovery(groups, len(facts) + len(duplicates), duplicates,
                            time.perf_counter() - started)


def collect_task_facts(image_ctx: ImageContext, *, comm: Optional[str] = None
                       ) -> Tuple[List[TaskFacts], Dict[int, int], Dict[int, int]]:
    """(facts per address space, pid -> ppid of every task, duplicate pid -> kept pid).

    Kernel threads (no ``mm``) are skipped; ``comm`` keeps only tasks with that name.
    """
    from volatility3.plugins.linux import pslist
    facts: List[TaskFacts] = []
    parents: Dict[int, int] = {}
    seen_mm: Dict[int, int] = {}
    duplicates: Dict[int, int] = {}
    with image_ctx.lock:  # vol3 contexts are not thread-safe
        for task in pslist.PsList.list_tasks(image_ctx.context, image_ctx.kernel.name):
            pid, ppid = int(task.tgid), int(task.get_parent_pid())
            parents[pid] = ppid
            mm = int(task.mm)
            if not mm or (comm is not None and _comm(task) != comm):
                continue
            if mm in seen_mm:
                duplicates[pid] = seen_mm[mm]
                continue
            seen_mm[mm] = pid
            facts.append(_task_facts(image_ctx, task, pid, ppid, mm))
    return facts, parents, duplicates


def _comm(task: Any) -> str:
    return str(task.comm.cast("string", max_length=16, errors="replace"))


def _task_facts(image_ctx: ImageContext, task: Any, pid: int, ppid: int, mm: int) -> TaskFacts:
    mm_obj = task.mm
    aslr = (int(mm_obj.start_code), int(mm_obj.mmap_base), int(mm_obj.start_stack))
    text_vma, header_vma = _exe_vmas(mm_obj)
    exe_path = _exe_path(image_ctx, text_vma, task)
    build_id, error = _read_build_id(image_ctx, task, header_vma)
    return TaskFacts(pid, ppid, _comm(task), mm, aslr, exe_path, build_id,
                     "elf_note" if build_id else None, error)


def _exe_vmas(mm_obj: Any) -> Tuple[Optional[Any], Optional[Any]]:
    """(VMA holding ``start_code``, the same file's VMA at file offset 0)."""
    start_code = int(mm_obj.start_code)
    vmas = list(mm_obj.get_vma_iter())
    text = next((v for v in vmas if int(v.vm_start) <= start_code < int(v.vm_end)), None)
    file_ptr = _int_field(text, "vm_file")
    if not file_ptr:
        return text, None
    header = next((v for v in vmas if _int_field(v, "vm_file") == file_ptr
                   and _int_field(v, "vm_pgoff") == 0), None)
    return text, header


def _int_field(obj: Any, name: str) -> int:
    """``int(obj.<name>)``; 0 for a missing object or an unreadable field."""
    if obj is None:
        return 0
    try:
        return int(getattr(obj, name))
    except Exception:  # noqa: BLE001 - an unreadable field reads as "absent"
        return 0


def _exe_path(image_ctx: ImageContext, vma: Optional[Any], task: Any) -> Optional[str]:
    from memdiver.core.image.adapters import UNRESOLVED_NAME, _vma_name
    if not _int_field(vma, "vm_file"):
        return None
    name = _vma_name(image_ctx, vma, task)
    return name if name and name != UNRESOLVED_NAME else None


def _read_build_id(image_ctx: ImageContext, task: Any,
                   header_vma: Optional[Any]) -> Tuple[Optional[str], Optional[str]]:
    """(build-id, why it is missing)."""
    if header_vma is None:
        return None, "no file-backed VMA at offset 0 for the executable"
    try:
        layer = image_ctx.context.layers[task.add_process_layer()]
        start, end = int(header_vma.vm_start), int(header_vma.vm_end)
        found = parse_build_id(lambda va, n: layer.read(va, n, pad=False), start, end - start)
    except Exception as exc:  # noqa: BLE001 - a non-resident header page is normal
        return None, f"header page unreadable: {type(exc).__name__}"
    return found, None if found else "no NT_GNU_BUILD_ID note"


__all__ = ["SiblingDiscovery", "SiblingGroup", "SiblingMember", "TaskFacts",
           "collect_task_facts", "discover_siblings", "fill_build_ids_from_exe",
           "group_shape", "group_siblings", "lineage_families", "member_roles", "pair_shape", "parse_build_id"]
