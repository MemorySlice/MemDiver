"""Layer adapters: the run table + captured-byte reads behind each image view (plan T1.2/T1.3).

One adapter per :class:`~memdiver.core.image.view_descriptor.ViewKind`, all
over an :class:`~memdiver.core.image.context.ImageContext`:

* physical — the image's physical address space (LiME/ELF segments, or the
  whole file for a raw image); everything it knows is CAPTURED.
* kernel — the kernel image (``_text`` .. ``_end``) and the direct map of every
  physical segment, classified through the kernel page tables.
* process — every VMA of one task, classified through its page tables; pages
  inside a VMA without a translation are NOT_RESIDENT (user decision
  2026-10-25), translated pages whose frame is not in the image are FAILED.

Imports Volatility 3 lazily through the context; never pickled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from memdiver.core.image.context import ImageContext
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: x86_64 base page size (log2).
PAGE_SHIFT = 12
#: VMA name when vol3 cannot walk the file's dentry/mount chain.
UNRESOLVED_NAME = "<unresolved>"
#: Direct-map base when the profile has no ``page_offset_base`` (no KASLR of it).
DEFAULT_PAGE_OFFSET = {48: 0xFFFF888000000000, 57: 0xFF11000000000000}


#: How an untranslated stretch inside a known range is labelled: a constant
#: state, a classifier yielding runs, or ``None`` (drop it: it reads as unmapped).
GapPolicy = Union[RunState, Callable[[Any, int, int], Iterator[LayerRun]], None]


def classify(layer: Any, start: int, length: int,
             missing: GapPolicy = RunState.NOT_RESIDENT) -> Iterator[LayerRun]:
    """Runs covering ``[start, start+length)`` of a translation ``layer``.

    Translated and backed by the image -> CAPTURED; translated but the target
    frame is not readable -> FAILED; no translation -> per ``missing``.
    """
    cursor, end = start, start + length
    for offset, size, mapped, mapped_size, below in layer.mapping(start, length,
                                                                    ignore_errors=True):
        lo, hi = max(offset, cursor), min(offset + size, end)
        if hi <= lo:
            continue
        yield from _gap_runs(missing, layer, cursor, lo)
        backed = layer.context.layers[below].is_valid(mapped, mapped_size)
        yield LayerRun(lo, hi - lo, RunState.CAPTURED if backed else RunState.FAILED)
        cursor = hi
    yield from _gap_runs(missing, layer, cursor, end)


def _gap_runs(missing: GapPolicy, layer: Any, lo: int, hi: int) -> Iterator[LayerRun]:
    if hi <= lo or missing is None:
        return
    if isinstance(missing, RunState):
        yield LayerRun(lo, hi - lo, missing)
    else:
        yield from missing(layer, lo, hi - lo)


def pte_gap_runs(layer: Any, start: int, length: int) -> Iterator[LayerRun]:
    """Label an untranslated stretch of an ANONYMOUS mapping from its page tables.

    MSL spec v1.1 Table 35: NotResident means "anonymous memory, not present and
    not swapped; content is zero". So an empty entry (at any level) is
    NOT_RESIDENT, while a non-present entry that still holds a value (a swap or
    migration entry, PROT_NONE, ...) is FAILED: its content exists but is not in
    the image. A missing upper-level entry covers its whole aligned block, which
    is skipped in one step.
    """
    cursor, end = start, start + length
    while cursor < end:
        state, block_end = _absent_entry(layer, cursor)
        stop = min(block_end, end)
        yield LayerRun(cursor, stop - cursor, state)
        cursor = stop


def _absent_entry(layer: Any, address: int) -> Tuple[RunState, int]:
    """(state, end of the block that shares the failing entry) for one address."""
    from volatility3.framework import exceptions
    page = 1 << PAGE_SHIFT
    try:
        layer.translate(address)
    except exceptions.PagedInvalidAddressException as exc:
        block = 1 << max(int(exc.invalid_bits), PAGE_SHIFT)
        state = RunState.NOT_RESIDENT if exc.entry == 0 else RunState.FAILED
        return state, (address // block + 1) * block
    except exceptions.InvalidAddressException:
        return RunState.FAILED, (address // page + 1) * page
    # mapping() reported no translation but translate() found one: be conservative.
    return RunState.FAILED, (address // page + 1) * page


class _LayerReader:
    """Shared ``read``/``close`` over one named layer of an ImageContext."""

    def __init__(self, image_ctx: ImageContext, layer_name: str) -> None:
        self._ctx = image_ctx
        self._layer = image_ctx.context.layers[layer_name]

    def read(self, address: int, length: int) -> bytes:
        with self._ctx.lock:
            return self._layer.read(address, length, pad=False)

    def close(self) -> None:
        """Nothing to release: the ImageContext is shared through its cache."""


class PhysicalAdapter(_LayerReader):
    def __init__(self, image_ctx: ImageContext) -> None:
        super().__init__(image_ctx, image_ctx.physical_layer)

    def runs(self) -> Sequence[LayerRun]:
        with self._ctx.lock:
            return physical_runs(self._layer)

    def describe(self) -> Dict[str, Any]:
        return {"view": "physical", **self._ctx.describe()}


def physical_runs(layer: Any) -> List[LayerRun]:
    """Segments of a physical layer; a flat file layer is one run."""
    end = layer.maximum_address + 1
    if not hasattr(layer, "mapping"):
        return [LayerRun(0, end, RunState.CAPTURED)]
    return [LayerRun(off, size, RunState.CAPTURED)
            for off, size, *_ in layer.mapping(0, end, ignore_errors=True)]


class KernelAdapter(_LayerReader):
    def __init__(self, image_ctx: ImageContext) -> None:
        super().__init__(image_ctx, image_ctx.kernel.layer_name)
        self._physical = image_ctx.context.layers[image_ctx.physical_layer]

    def runs(self) -> Sequence[LayerRun]:
        with self._ctx.lock:
            return self._runs_locked()

    def _runs_locked(self) -> Sequence[LayerRun]:
        kernel = self._ctx.kernel
        # Symbol addresses are masked to the VA width (as in stock vol3); the
        # view's coordinates are canonical kernel VAs.
        text = self._ctx.canonical_kernel_va(kernel.get_absolute_symbol_address("_text"))
        end = self._ctx.canonical_kernel_va(kernel.get_absolute_symbol_address("_end"))
        runs = list(classify(self._layer, text, end - text, missing=None))
        base = self._page_offset_base()
        for seg in physical_runs(self._physical):
            runs.extend(classify(self._layer, base + seg.start, seg.length, missing=None))
        return runs

    def _page_offset_base(self) -> int:
        kernel = self._ctx.kernel
        if kernel.has_symbol("page_offset_base"):
            return int(kernel.object_from_symbol("page_offset_base"))
        return DEFAULT_PAGE_OFFSET[self._ctx.kernel_paging.va_bits]

    def describe(self) -> Dict[str, Any]:
        with self._ctx.lock:
            return {"view": "kernel", "page_offset_base": self._page_offset_base(),
                    **self._ctx.describe()}


@dataclass(frozen=True)
class Vma:
    """One VMA with the facts an ``.msl`` extraction needs."""

    start: int
    end: int
    name: str
    protection: str      # "rwx"-style, from vol3
    is_heap: bool        # overlaps mm.start_brk .. mm.brk (vol3 does not label it)
    file_backed: bool = False   # vm_file set: absent pages have content in the file


def _vma_gap_policy(vma: Vma) -> GapPolicy:
    """File-backed absent pages hold file content (FAILED); anonymous ones are split by PTE."""
    return RunState.FAILED if vma.file_backed else pte_gap_runs


class ProcessAdapter(_LayerReader):
    def __init__(self, image_ctx: ImageContext, pid: int) -> None:
        with image_ctx.lock:
            self._task = find_task(image_ctx, pid)
            layer_name = self._task.add_process_layer()
        if layer_name is None:
            raise CapabilityError(f"pid {pid} has no address space (kernel thread?)",
                                  category=ErrorCategory.INVALID_INPUT)
        super().__init__(image_ctx, layer_name)
        self._pid = pid
        self._vmas: Optional[List[Vma]] = None

    def vmas(self) -> List[Vma]:
        with self._ctx.lock:
            if self._vmas is None:
                self._vmas = list(_iter_vmas(self._ctx, self._task))
            return self._vmas

    def runs(self) -> Sequence[LayerRun]:
        with self._ctx.lock:
            return [run for vma in self.vmas()
                    for run in classify(self._layer, vma.start, vma.end - vma.start,
                                        missing=_vma_gap_policy(vma))]

    def describe(self) -> Dict[str, Any]:
        with self._ctx.lock:
            comm = self._task.comm.cast("string", max_length=16, errors="replace")
            return {"view": "process", "pid": self._pid, "comm": str(comm),
                    "process_dtb": self._layer.config["page_map_offset"],
                    "vma_count": len(self.vmas()), **self._ctx.describe()}


def find_task(image_ctx: ImageContext, pid: int) -> Any:
    from volatility3.plugins.linux import pslist
    for task in pslist.PsList.list_tasks(image_ctx.context, image_ctx.kernel.name):
        if int(task.pid) == pid:
            return task
    raise CapabilityError(f"pid {pid} is not in the task list of this image",
                          category=ErrorCategory.INVALID_INPUT)


def _iter_vmas(image_ctx: ImageContext, task: Any) -> Iterator[Vma]:
    mm = task.mm
    brk = (int(mm.start_brk), int(mm.brk))
    for vma in mm.get_vma_iter():
        start, end = int(vma.vm_start), int(vma.vm_end)
        is_heap = brk[0] < brk[1] and start < brk[1] and brk[0] < end
        name = "[heap]" if is_heap else _vma_name(image_ctx, vma, task)
        yield Vma(start, end, name, vma.get_protection(), is_heap, _is_file_backed(vma))


def _is_file_backed(vma: Any) -> bool:
    try:
        return int(vma.vm_file) != 0
    except Exception:  # noqa: BLE001 - unreadable vm_file: treat as file-backed (FAILED, never zero)
        return True


def _vma_name(image_ctx: ImageContext, vma: Any, task: Any) -> str:
    """vol3's VMA name; a smashed dentry/mount in a real image must not kill the view."""
    try:
        return vma.get_name(image_ctx.context, task) or ""
    except Exception:  # noqa: BLE001 - any vol3 walk failure means "name unknown"
        return UNRESOLVED_NAME


def adapter_for_view(image_ctx: ImageContext, descriptor: ViewDescriptor) -> Any:
    if descriptor.view is ViewKind.PHYSICAL:
        return PhysicalAdapter(image_ctx)
    if descriptor.view is ViewKind.KERNEL and descriptor.profile is None:
        from memdiver.core.image.pakunoda_view import NoIsfKernelAdapter
        return NoIsfKernelAdapter(image_ctx, descriptor.paging)
    if not image_ctx.has_kernel:
        raise CapabilityError(f"a {descriptor.view.value} view needs a kernel profile (ISF)",
                              category=ErrorCategory.UNSUPPORTED)
    if descriptor.view is ViewKind.KERNEL:
        return KernelAdapter(image_ctx)
    assert descriptor.pid is not None  # enforced by ViewDescriptor
    return ProcessAdapter(image_ctx, descriptor.pid)
