"""Name-based region classification (Android / Linux / macOS mapping names).

A mapping's *name* (the ``/proc/<pid>/maps`` path column, an ELF core's
NT_FILE path, or a VAS_MAP ``mapped_path``) is the only portable signal that
separates, for example, an Android app's native heap (``[anon:scudo:*]``)
from the zygote-inherited ART runtime (``[anon:dalvik-zygote space]``). The
stored ``RegionType`` cannot: ``core.proc_maps_parser`` types every
``[anon:...]`` mapping as OTHER, and memslicer stores most of them as Anon.

:func:`classify_mapping_name` turns a name into a selection category
*override* (or ``None`` = "the name says nothing more than the stored
type"). The rules are a port of memslicer's
``acquirer/region_classify.classify_name`` with the categories MemDiver's
selection needs; there is deliberately no runtime dependency on memslicer.
The shared test vectors live in ``tests/fixtures/region_name_vectors.json``.

Deliberately left without an override (they keep today's category):

* ``[anon:.bss]`` -- app native globals live there;
* ``/dev/binder*`` (and other ``*binder*`` devices), ``/dev/shm/*``,
  ``/dev/zero``, non-dalvik ``/dev/ashmem/*`` and non-JIT ``/memfd:*``;
* app files (``/data/app/**``) and unknown ``[anon:X]`` labels.

:func:`legacy_live_region_type` reproduces the ``RegionType`` that memslicer
releases before name classification stored for a mapping name, so alignment
keys of new memslicer captures can be folded back onto the old key class.
"""

from __future__ import annotations

import bisect
import re
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Tuple

from .enums import RegionType

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .region_select import RegionCategory

PLATFORM_ANDROID = "android"
PLATFORM_LINUX = "linux"

_DELETED_SUFFIX = " (deleted)"
_ANON_LABEL = re.compile(r"^\[anon(?:_shmem)?:(.*)\]$")
_HEAP_NAME = re.compile(r"^\[heap(?::\d+)?\]$")
_STACK_NAME = re.compile(r"^\[stack(?::\d+)?\]$")

_KERNEL_NAMES = frozenset({
    "[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]", "[vectors]",
    "[sigpage]", "[uprobes]",
})

_HEAP_LABEL_PREFIXES = ("scudo:", "jemalloc", "GWP-ASan", "bionic_alloc",
                        "partition_alloc")
_STACK_LABEL_PREFIXES = ("stack_and_tls:", "thread signal stack",
                         "bionic TLS", "thread stack")
_RUNTIME_LABEL_PREFIXES = ("cfi shadow", "linker_alloc",
                           "System property context nodes")

_DALVIK_PREFIX = "dalvik-"
_DALVIK_JIT_MARKERS = ("jit-code-cache", "data-code-cache")
_DALVIK_NON_HEAP = re.compile(r"bitmap|\bmap\b|\b(?:live|mark) stack\b")

# Where Android keeps the boot image / platform code (never app data).
_BOOT_PREFIXES = (
    "/system/", "/system_ext/", "/product/", "/vendor/", "/apex/",
    "/data/dalvik-cache/", "/data/misc/apexdata/com.android.art/dalvik-cache/",
)
_BOOT_CODE_SUFFIXES = (".art", ".oat", ".vdex", ".odex")
_ICU_PREFIXES = ("/system/usr/icu/", "/apex/com.android.i18n/etc/icu/")

_ASHMEM_PREFIX = "/dev/ashmem/"
_JIT_MEMFD_PREFIX = "/memfd:jit-"
_UNTOUCHED_DEVICE_PREFIXES = ("/dev/shm/", "/memfd:")
_RUNTIME_PSEUDO_PREFIXES = ("/dev/", "/dmabuf", "anon_inode:")

# Strong Android markers for :func:`looks_android` (never seen on Linux).
_ANDROID_NAME_PREFIXES = (
    "[anon:dalvik-", "[anon:scudo:", "[anon:stack_and_tls:",
    "[anon:bionic", "/dev/ashmem/", "/apex/", "/system/bin/linker",
    "/system/bin/app_process", "/system/lib64/", "/system/lib/",
    "/system/framework/", "/data/dalvik-cache/", "/dev/__properties__",
)


# -- name helpers ---------------------------------------------------------------


def strip_deleted(name: str) -> str:
    """*name* without a trailing ``" (deleted)"`` marker."""
    if name.endswith(_DELETED_SUFFIX):
        return name[: -len(_DELETED_SUFFIX)]
    return name


def anon_label(name: str) -> Optional[str]:
    """``X`` of ``"[anon:X]"`` / ``"[anon_shmem:X]"``, else ``None``."""
    match = _ANON_LABEL.match(name)
    return match.group(1) if match else None


# -- classification -------------------------------------------------------------


def _categories():
    from .region_select import RegionCategory  # deferred: avoids an import cycle
    return RegionCategory


def _is_boot_path(path: str) -> bool:
    return path.startswith(_BOOT_PREFIXES)


def _classify_dalvik(rest: str) -> "RegionCategory":
    """ART label after ``dalvik-``: heap space, boot image or metadata."""
    cat = _categories()
    if rest.startswith("/"):  # an image: boot image vs app image
        if _is_boot_path(rest):
            return cat.RUNTIME
        return cat.HEAP if rest.endswith(".art") else cat.RUNTIME
    if any(marker in rest for marker in _DALVIK_JIT_MARKERS):
        return cat.RUNTIME
    if (" space" in rest and "zygote" not in rest
            and not _DALVIK_NON_HEAP.search(rest)):
        return cat.HEAP
    return cat.RUNTIME  # zygote space, bitmaps, card table, LinearAlloc, ...


def _classify_anon_label(label: str) -> Optional["RegionCategory"]:
    cat = _categories()
    if label == ".bss":
        return None
    if "malloc" in label or label.startswith(_HEAP_LABEL_PREFIXES):
        return cat.HEAP
    if label.startswith(_DALVIK_PREFIX):
        return _classify_dalvik(label[len(_DALVIK_PREFIX):])
    if label.startswith(_STACK_LABEL_PREFIXES):
        return cat.STACK
    if label.startswith(_RUNTIME_LABEL_PREFIXES):
        return cat.RUNTIME
    return None


def _is_untouched_device(name: str) -> bool:
    """Shared-memory style devices that may hold app data: no override."""
    if name == "/dev/zero" or name.startswith(_UNTOUCHED_DEVICE_PREFIXES):
        return True
    return name.startswith("/dev/") and "binder" in name.rsplit("/", 1)[-1]


def _classify_pseudo_path(name: str) -> Optional["RegionCategory"]:
    cat = _categories()
    if name.startswith(_ASHMEM_PREFIX):
        rest = name[len(_ASHMEM_PREFIX):]
        if rest.startswith(_DALVIK_PREFIX):
            return _classify_dalvik(rest[len(_DALVIK_PREFIX):])
        return None
    if name.startswith(_JIT_MEMFD_PREFIX):
        return cat.RUNTIME
    if _is_untouched_device(name):
        return None
    if name.startswith(_RUNTIME_PSEUDO_PREFIXES):
        return cat.RUNTIME
    return None


def _classify_file_path(name: str) -> Optional["RegionCategory"]:
    if name.startswith(_ICU_PREFIXES):
        return _categories().RUNTIME
    if _is_boot_path(name) and name.endswith(_BOOT_CODE_SUFFIXES):
        return _categories().RUNTIME
    return None


def classify_mapping_name(name: Optional[str]) -> Optional["RegionCategory"]:
    """Selection-category override implied by a mapping *name*, or ``None``.

    ``None`` means the name adds nothing; the caller keeps the category the
    stored type / protection give. See the module docstring for the rules
    and the deliberate exclusions.
    """
    if not name:
        return None
    name = strip_deleted(name.strip())
    cat = _categories()
    if name in _KERNEL_NAMES:
        return cat.RUNTIME
    if _HEAP_NAME.match(name):
        return cat.HEAP
    if _STACK_NAME.match(name):
        return cat.STACK
    label = anon_label(name)
    if label is not None:
        return _classify_anon_label(label)
    pseudo = _classify_pseudo_path(name)
    if pseudo is not None or name.startswith(("/dev/", "/memfd:")):
        return pseudo
    return _classify_file_path(name)


def looks_android(names: Iterable[Optional[str]]) -> bool:
    """True when any mapping name carries an unmistakable Android marker."""
    return any(name and strip_deleted(name).startswith(_ANDROID_NAME_PREFIXES)
               for name in names)


def platform_for_names(names: Iterable[Optional[str]],
                       default: Optional[str] = PLATFORM_LINUX
                       ) -> Optional[str]:
    """``"android"`` when :func:`looks_android`, else *default*."""
    return PLATFORM_ANDROID if looks_android(names) else default


# -- legacy memslicer region types ------------------------------------------------


def legacy_live_region_type(name: Optional[str]) -> int:
    """``RegionType`` memslicer stored for *name* before name classification.

    Exact port of memslicer's original ``engine.classify_region`` (substring
    and suffix tests on the raw name, ``" (deleted)"`` NOT stripped).
    """
    if not name:
        return int(RegionType.ANONYMOUS)
    if "[heap]" in name:
        return int(RegionType.HEAP)
    if "[stack]" in name:
        return int(RegionType.STACK)
    if name.endswith((".so", ".dylib", ".dll", ".exe")):
        return int(RegionType.IMAGE)
    if "/" in name or "\\" in name:
        return int(RegionType.MAPPED_FILE)
    return int(RegionType.UNKNOWN)


# -- VAS_MAP name lookup ------------------------------------------------------------


class MappingNameIndex:
    """Name of the VAS entry containing an address (bisect over entry bases).

    Built from ``(base, size, name)`` triples, e.g. VAS_MAP entries. A region
    whose base lies in no entry has no name (``None``); a covered anonymous
    entry has the empty name ``""``.
    """

    def __init__(self, entries: Iterable[Tuple[int, int, str]]) -> None:
        ordered = sorted((int(b), int(s), n or "") for b, s, n in entries)
        self._starts: List[int] = [e[0] for e in ordered]
        self._entries: Sequence[Tuple[int, int, str]] = ordered

    def __len__(self) -> int:
        return len(self._entries)

    def name_for(self, base: int) -> Optional[str]:
        idx = bisect.bisect_right(self._starts, base) - 1
        if idx < 0:
            return None
        start, size, name = self._entries[idx]
        return name if start <= base < start + max(size, 1) else None

    @classmethod
    def from_vas_entries(cls, entries) -> "MappingNameIndex":
        """From :class:`~memdiver.msl.types.MslVasEntry` objects."""
        return cls((e.base_addr, e.region_size, e.mapped_path)
                   for e in entries)
