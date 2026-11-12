"""Which process memory a ``memdiver.*`` process plugin reads, and how.

Shared Volatility 3 plumbing for the process-centric plugins (``memdiver.ssh``,
``memdiver.wireguard_go``): a ``.msl`` process slice stacked by
``memdiver_stackers.MslStacker`` is one target, a Linux memory image gives one target per
selected task (``--pid`` or a process-name filter). Only writable mappings are read unless the
caller asks for all regions (secrets never live in read-only file mappings), at most
``budget`` bytes per process.

Import rule of this directory: standard library, ``volatility3`` and sibling modules only.
"""
import logging
from typing import Callable, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)

VM_WRITE = 0x2
MSL_WRITE = 0x2
READ_CHUNK = 16 << 20
DEFAULT_MAX_MB = 1024


class PrimaryOrKernelLayer(requirements.TranslationLayerRequirement):
    """Mandatory layer requirement that the kernel module's layer also satisfies (so the
    LayerStacker runs, and on a kernel image the symbol automagic can build ``kernel``)."""

    def unsatisfied(self, context, config_path):
        own = interfaces.configuration.path_join(config_path, self.name)
        kernel_layer = interfaces.configuration.path_join(config_path, "kernel", "layer_name")
        if context.config.get(own, None) is None and context.config.get(kernel_layer, None):
            return {}
        return super().unsatisfied(context, config_path)


def target_requirements(pid_description: str) -> List[interfaces.configuration.RequirementInterface]:
    """Which process to read, shared by every process plugin: kernel, layer and ``--pid``."""
    return [
        requirements.ModuleRequirement(
            name="kernel", description="Linux kernel (for --pid on a memory image)",
            architectures=["Intel32", "Intel64"], optional=True),
        PrimaryOrKernelLayer(name="primary", description="Memory layer"),
        requirements.ListRequirement(
            name="pid", element_type=int, optional=True, description=pid_description),
    ]


def read_requirements() -> List[interfaces.configuration.RequirementInterface]:
    """How much of it to read, shared by every process plugin: ``--all-regions``, ``--max-mb``."""
    return [
        requirements.BooleanRequirement(
            name="all_regions", optional=True, default=False,
            description="Also read non-writable mappings"),
        requirements.IntRequirement(
            name="max_mb", optional=True, default=DEFAULT_MAX_MB,
            description="Read at most this many MiB per process"),
    ]


# ``write_text`` lives in the kernel helpers so ``linux.*`` plugins never import a process plugin;
# it is re-exported here for ``memdiver.ssh`` / ``memdiver.wireguard_go``.
from ..linux.kernel_common import write_text  # noqa: E402,F401


class Target(object):
    """One process to analyse: its layer, sections (``None`` = whole layer), pid and name."""

    def __init__(self, layer_name, sections, pid, name, scope):
        self.layer_name = layer_name
        self.sections = sections
        self.pid = pid
        self.name = name
        self.scope = scope


def kernel_module(context, config):
    name = config.get("kernel", None)
    if not name or not isinstance(name, str):
        return None
    try:
        return context.modules[name]
    except (KeyError, AttributeError):
        return None


def base_layer(context, config) -> str:
    primary = config.get("primary", None)
    if primary:
        return primary
    module = kernel_module(context, config)
    if module is not None:
        return module.layer_name
    name = config.get("kernel.layer_name", None)
    if name:
        return name
    raise ValueError("no memory layer was stacked; pass -f <image>")


def targets(context, config, plugin_name: str, wanted: Callable[[str], bool]) -> List[Target]:
    """The ``.msl`` slice, or the image's tasks selected by ``--pid`` or by ``wanted(comm)``."""
    base = base_layer(context, config)
    metadata = context.layers[base].metadata
    pids = config.get("pid", None) or []
    all_regions = bool(config.get("all_regions"))
    if metadata.get("msl"):
        return [msl_target(context, base, metadata, pids, all_regions)]
    if kernel_module(context, config) is None:
        raise ValueError("%s needs a .msl process slice or a Linux image with symbols (it "
                         "reads process virtual memory)" % plugin_name)
    return process_targets(context, config["kernel"], pids, wanted, all_regions)


def msl_target(context, base, metadata, pids, all_regions) -> Target:
    pid = metadata.get("pid")
    if pids and pid is not None and int(pid) not in pids:
        vollog.warning("--pid %s: this .msl slice holds pid %s; scanning it anyway", pids, pid)
    layer = context.layers[base]
    sections = None
    if not all_regions and hasattr(layer, "region_map"):
        sections = [(r.start, r.end - r.start) for r in layer.region_map()
                    if r.protection & MSL_WRITE and r.end > r.start]
    name = (metadata.get("msl_exe_path") or "").rsplit("/", 1)[-1]
    return Target(base, sections, pid, name, "msl:%s" % (pid if pid is not None else "?"))


def process_targets(context, kernel, pids, wanted, all_regions) -> List[Target]:
    from volatility3.plugins.linux import pslist  # lazy: only on a kernel image

    if pids:
        tasks = pslist.PsList.list_tasks(context, kernel,
                                         pslist.PsList.create_pid_filter(list(pids)))
    else:
        tasks = (t for t in pslist.PsList.list_tasks(context, kernel) if wanted(comm(t)))
    found = []
    for task in tasks:
        try:
            if not task.mm:
                continue
            layer = task.add_process_layer()
        except exceptions.InvalidAddressException:
            continue
        if layer:
            found.append(Target(layer, vma_sections(task, all_regions), int(task.pid),
                                comm(task), "process:%d" % int(task.pid)))
    return found


def comm(task) -> str:
    try:
        return task.comm.cast("string", max_length=16, errors="replace")
    except (exceptions.InvalidAddressException, AttributeError):
        return ""


def vma_sections(task, all_regions) -> Optional[List[Tuple[int, int]]]:
    sections = []
    try:
        for vma in task.mm.get_vma_iter():
            start, end = int(vma.vm_start), int(vma.vm_end)
            if end <= start:
                continue
            if all_regions or int(vma.vm_flags) & VM_WRITE:
                sections.append((start, end - start))
    except (exceptions.InvalidAddressException, AttributeError) as err:
        vollog.warning("could not list the VMAs of pid %s: %s", task.pid, err)
        return None
    return sections


def target_segments(context, config, target: Target) -> List[Tuple[int, bytes]]:
    """:func:`read_segments` of ``target`` within the ``--max-mb`` budget."""
    budget = int(config.get("max_mb") or DEFAULT_MAX_MB) << 20
    return read_segments(context.layers[target.layer_name], target.sections, budget, target.pid)


def read_segments(layer, sections, budget: int, pid=None) -> List[Tuple[int, bytes]]:
    """``(va, bytes)`` of the readable parts of ``sections``, at most ``budget`` bytes."""
    if sections is None:
        sections = [(layer.minimum_address, layer.maximum_address - layer.minimum_address)]
    pieces = []
    for start, size in sections:
        for offset, length in mapped_runs(layer, start, size):
            if budget <= 0:
                vollog.warning("pid %s: --max-mb reached, rest of the process not read", pid)
                return pieces
            length = min(length, budget)
            try:
                data = layer.read(offset, length)
            except exceptions.InvalidAddressException:
                continue
            budget -= length
            pieces.append((offset, data))
    return pieces


def mapped_runs(layer, start, size) -> Iterable[Tuple[int, int]]:
    """Readable runs ``(va, length)`` inside a section, contiguous pieces joined."""
    run_start, run_end = None, None
    try:
        for offset, length, _m_offset, _m_length, _layer in layer.mapping(start, size,
                                                                            ignore_errors=True):
            if run_end == offset:
                run_end += length
                continue
            if run_start is not None:
                yield from _chunks(run_start, run_end)
            run_start, run_end = offset, offset + length
    except exceptions.InvalidAddressException:
        pass
    if run_start is not None:
        yield from _chunks(run_start, run_end)


def _chunks(start, end):
    while start < end:
        yield start, min(READ_CHUNK, end - start)
        start += READ_CHUNK


# --- task selection with --comm and address-space dedup (memdiver.page_sharing) -----------

def comm_requirement(description: str = "Process names (task comm, exact match); "
                                        "repeatable") -> interfaces.configuration.RequirementInterface:
    """``--comm``: select tasks by name (combined with ``--pid`` as a union)."""
    return requirements.ListRequirement(name="comm", element_type=str, optional=True,
                                        description=description)


def selected_tasks(context, kernel_name: str, pids=None, comms=None) -> List:
    """Thread-group leaders with an address space, selected by ``pids`` OR ``comms``
    (both empty: every task with an ``mm``). Same pslist walk as :func:`process_targets`."""
    from volatility3.plugins.linux import pslist  # lazy: only on a kernel image

    pids = set(int(p) for p in (pids or ()))
    comms = set(comms or ())
    found = []
    for task in pslist.PsList.list_tasks(context, kernel_name):
        try:
            if not task.mm:
                continue
            pid = int(task.pid)
        except exceptions.InvalidAddressException:
            continue
        if (pids or comms) and pid not in pids and comm(task) not in comms:
            continue
        found.append(task)
    return found


def dedup_by_mm(tasks) -> Tuple[List, dict]:
    """One task per address space (threads / ``CLONE_VM`` children share an ``mm``): the
    first wins. Returns the kept tasks and ``{dropped pid: kept pid}``."""
    kept, owner, dropped = [], {}, {}
    for task in tasks:
        try:
            mm = int(task.mm)
        except exceptions.InvalidAddressException:
            continue
        if mm in owner:
            dropped[int(task.pid)] = owner[mm]
            continue
        owner[mm] = int(task.pid)
        kept.append(task)
    return kept, dropped
