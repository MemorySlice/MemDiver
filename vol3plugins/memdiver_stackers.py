"""Volatility 3 stackers for the capture formats MemDiver adds.

Stock vol loads this file as ``volatility3.plugins.memdiver_stackers`` (``vol -p <this dir>``).
It is deliberately NOT named ``memdiver_layers.py``: ``app/tools_vol3_dev.py`` writes an LA57
shim of that name into ``<cfg>_plugins/``, and two files that load as the same
``volatility3.plugins.<name>`` cannot both be on ``-p`` (vol silently skips the second).
``LayerStacker`` then offers every stacker here the file layer under ``-f``, ordered by
``stack_order``. One stacker per format. Each stacker:

* decides from a few header bytes the base layer already holds, and returns ``None`` at
  once for anything else, with no MemDiver import (``vol -p <dir> -h`` and every run on
  a non-matching image stay as fast as stock vol);
* imports its layers lazily, only after the header matched, and builds them from the
  config defaults the layer documents.

Stackers are never written into a saved config (only the layers they build are), so the
stackers need no canonical class path. The two LA57 layer classes below are written into
saved configs, so they get one, exactly as in ``msl_layer`` (see "Class path" there):
:data:`CANONICAL_MODULE`, the name stock vol gives this file.

LA57 fallback
-------------
Volatility 3 2.27/2.28 has no 5-level (LA57) Intel layer. On an x86_64 kernel that runs
5-level paging its automagic finds the right DTB and KASLR shifts, stacks a 4-level layer,
and every plugin silently returns nothing. :class:`LinuxLA57IntelStacker` runs right after
the stock Linux stackers. When the layer they built is a plain 4-level ``LinuxIntel32e``
(or ``Intel32e`` from VMCOREINFO) that cannot read the kernel's own ``linux_banner`` and
``init_task.comm`` back, while the same configuration walked with five levels can, it
stacks the 5-level twin on top, so the plugin is handed the 5-level layer. It does nothing
when the volatility3 in use already knows LA57 (upstream PR #1991, "Detect Linux LA57 from
page tables and use 46-bit PFNs", adds ``intel.LinuxIntel32e_LA57``), and it never touches
an image whose 4-level layer reads the kernel back, so 4-level results stay identical.
Should both depths ever read the kernel back, the kernel's own ``__pgtable_l5_enabled``
decides, as in PR #1991's tie case (read through the 4-level layer: the kernel-text mapping
is the same under both depths).

A config saved with ``--save-config`` names an LA57 class from this file, so replaying it
with ``-c`` needs ``-p <this dir>`` again (without it, vol reports ``kernel.layer_name``
unsatisfied). Pickling (``--parallelism processes``): a spawned worker cannot import
``volatility3.plugins.memdiver_stackers`` (the ``-p`` directory is not on its plugin path),
so the LA57 layers pickle through :func:`_rebuild_layer`, published under
:data:`MEMDIVER_MODULE`, exactly as ``msl_layer`` does. The worker therefore needs MemDiver
importable; without it the worker fails to unpickle (and stock vol waits for it).

An error is reported as one log line by the layer that failed, and the exception is then
raised. ``LayerStacker`` swallows it at a high verbosity level, which is the house
pattern (compare ``AVMLStacker``).
"""

import logging
import sys
from typing import Any, Dict, Optional, Type

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)

#: The one module name the LA57 layer classes answer to (see the module docstring).
CANONICAL_MODULE = "volatility3.plugins.memdiver_stackers"
#: The name MemDiver imports this file under; always importable, so pickles point here.
MEMDIVER_MODULE = "memdiver.vol3plugins.memdiver_stackers"
#: Kernel variable that holds 1 when the kernel booted with 5-level paging (>= 4.17).
L5_FLAG_SYMBOL = "__pgtable_l5_enabled"

#: First 8 bytes of every Memory Slice file (MSL spec 3.1).
MSL_MAGIC = b"MEMSLICE"


def _starts_with(layer: interfaces.layers.DataLayerInterface, magic: bytes) -> bool:
    """Whether ``layer`` holds ``magic`` at offset 0."""
    try:
        return layer.read(0, len(magic)) == magic
    except exceptions.InvalidAddressException:
        return False


class MslStacker(interfaces.automagic.StackerLayerInterface):
    """Stacks ``MslVasLayer`` and ``MslLayer`` on a file that starts with ``MEMSLICE``.

    The layers open the capture with MemDiver's reader, or with the standard-library
    ``msl_slim`` reader when MemDiver is not importable (see "Without MemDiver" in
    ``msl_layer``); the stacked layers are the same either way.
    """

    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        if not _starts_with(context.layers[layer_name], MSL_MAGIC):
            return None
        from . import msl_layer

        join = interfaces.configuration.path_join
        vas_name = context.layers.free_layer_name("MslVasLayer")
        context.config[join(vas_name, "base_layer")] = layer_name
        context.add_layer(msl_layer.MslVasLayer(context, vas_name, vas_name))

        top_name = context.layers.free_layer_name("MslLayer")
        context.config[join(top_name, "base_layer")] = vas_name
        return msl_layer.MslLayer(context, top_name, top_name)


# --------------------------------------------------------------------------- LA57 fallback


class _PortablePickle:
    """A pickle a spawned worker without this plugin directory can load (see the docstring)."""

    def __reduce__(self) -> Any:
        # (factory, args, state): pickle restores ``__dict__`` after the factory returns.
        return (_rebuild_layer, (type(self).__name__,), self.__dict__.copy())


class Intel32eLA57(_PortablePickle, intel.Intel32e):
    """``Intel32e`` with LA57: a fifth 9-bit level on top, 57-bit virtual addresses.

    Every derived value (``maximum_address``, ``address_mask``, canonicalisation and the
    walk) follows from ``_maxvirtaddr`` and ``_structure``; MemDiver's
    ``core/image/paging.py`` (``LinuxIntel5Level``) defines the same table in-process.
    """

    _maxvirtaddr = 57
    _structure = [("page map layer 5", 9, False)] + list(intel.Intel32e._structure)


#: 4-level class the stock stackers build (exact type) -> its 5-level twin.
LA57_TWIN: Dict[Type[intel.Intel], Type[intel.Intel]] = {intel.Intel32e: Intel32eLA57}

#: ``None`` on older volatility3 trees (e.g. the 2.x arm64 fork the dmcrypt and wireguard
#: tests drive), which have no ``LinuxIntel32e``; this file must still load there.
_LINUX_INTEL32E: Optional[Type[intel.Intel]] = getattr(intel, "LinuxIntel32e", None)

if _LINUX_INTEL32E is not None:

    class LinuxIntel32eLA57(_PortablePickle, _LINUX_INTEL32E):  # type: ignore[misc,valid-type]
        """``LinuxIntel32e`` with LA57. Keeps the 46-bit PFN mask it inherits.

        As upstream PR #1991 argues for its ``LinuxIntel32e_LA57``: ``__PHYSICAL_MASK_SHIFT``
        is 52 on 5-level kernels, but the AMD SME C-bit or the Intel TDX shared bit can sit
        at bit 51, and a 52-bit mask would read it as part of the PFN.
        """

        _maxvirtaddr = 57
        _structure = Intel32eLA57._structure

    LA57_TWIN[_LINUX_INTEL32E] = LinuxIntel32eLA57

#: The upstream 5-level class; when the running volatility3 has it, this fallback is off.
UPSTREAM_LA57_CLASS = "LinuxIntel32e_LA57"


def upstream_supports_la57() -> bool:
    """Whether the running volatility3 stacks 5-level layers itself (PR #1991 or later)."""
    return hasattr(intel, UPSTREAM_LA57_CLASS)


def reads_kernel_back(layer: interfaces.layers.DataLayerInterface, table: Any,
                      aslr_shift: int) -> bool:
    """Whether ``layer`` reads ``linux_banner`` and ``init_task.comm`` back.

    The same read-back test as ``_self_test`` in MemDiver's ``core/image/paging.py``. A
    4-level walk of a 5-level table (or the reverse) lands on the wrong tables, so on every
    measured image exactly one depth passes. (PR #1991 instead checks that the kernel's
    top-level table maps itself; both need the kernel's symbols.)
    """
    checks = [("linux_banner", 0, b"Linux version")]
    if "init_task" in table.symbols and "task_struct" in table.types:
        comm = table.get_type("task_struct").relative_child_offset("comm")
        checks.append(("init_task", comm, b"swapper"))
    for symbol, delta, expected in checks:
        if symbol not in table.symbols:
            return False
        va = table.get_symbol(symbol).address + aslr_shift + delta
        try:
            if layer.read(va, len(expected), pad=False) != expected:
                return False
        except exceptions.InvalidAddressException:
            return False
    return True


def l5_flag_set(layer: interfaces.layers.DataLayerInterface, table: Any,
                aslr_shift: int) -> bool:
    """Whether ``__pgtable_l5_enabled`` reads non-zero through ``layer`` (False if absent)."""
    if L5_FLAG_SYMBOL not in table.symbols:
        return False
    va = table.get_symbol(L5_FLAG_SYMBOL).address + aslr_shift
    try:
        return int.from_bytes(layer.read(va, 4, pad=False), "little") != 0
    except exceptions.InvalidAddressException:
        return False


def _kernel_table(context: interfaces.context.ContextInterface,
                  layer: interfaces.layers.DataLayerInterface) -> Optional[Any]:
    """The symbol table the stock stacker loaded for ``layer``'s banner, else ``None``.

    Both stock Linux stackers store the banner in the layer config and leave the table
    they loaded (``LintelStacker*``) in the symbol space, so no ISF is parsed twice.
    """
    from volatility3.framework.automagic import symbol_cache

    banner = layer.config.get("kernel_banner", None)
    if not banner:
        return None
    location = symbol_cache.load_cache_manager().find_location(
        banner.encode("latin-1"), "linux")
    if not location:
        return None
    for name in context.symbol_space:
        table = context.symbol_space[name]
        if table.config.get("isf_url", None) == location:
            return table
    return None


def _build_twin(context: interfaces.context.ContextInterface,
                layer: interfaces.layers.DataLayerInterface,
                twin_class: Type[intel.Intel]) -> interfaces.layers.DataLayerInterface:
    """``twin_class`` built from a copy of ``layer``'s configuration, beside it."""
    join = interfaces.configuration.path_join
    parent_path = layer.config_path.rpartition(".")[0]
    name = context.layers.free_layer_name("IntelLayerLA57")
    config_path = join(parent_path, name) if parent_path else name
    context.config.merge(config_path, layer.config)
    return twin_class(context, config_path=config_path, name=name,
                      metadata={"os": "Linux"})


class LinuxLA57IntelStacker(interfaces.automagic.StackerLayerInterface):
    """Restacks a 4-level Linux kernel layer as 5-level when only five levels read it.

    The name ends in ``IntelStacker`` on purpose: MemDiver's in-process stacking
    (``core/image/context.py``) skips those stackers and picks the depth itself.
    """

    stack_order = 36  # after LinuxIntelStacker (35) and LinuxIntelVMCOREINFOStacker (34)
    exclusion_list = ["mac", "windows"]

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        layer = context.layers[layer_name]
        twin_class = LA57_TWIN.get(type(layer))
        if twin_class is None or upstream_supports_la57():
            return None
        table = _kernel_table(context, layer)
        if table is None:
            vollog.debug("LA57 fallback: no kernel symbol table for %s", layer_name)
            return None
        aslr_shift = layer.config.get("kernel_virtual_offset", 0) or 0
        four_level_reads = reads_kernel_back(layer, table, aslr_shift)
        if four_level_reads and not l5_flag_set(layer, table, aslr_shift):
            return None
        twin = _build_twin(context, layer, twin_class)
        if not reads_kernel_back(twin, table, aslr_shift):
            vollog.debug("LA57 fallback: 5-level walk does not read the kernel back at DTB %#x",
                         layer.config.get("page_map_offset", 0))
            return None
        vollog.info("LA57 fallback: kernel runs 5-level paging; stacked %s on %s",
                    twin_class.__name__, layer_name)
        return twin


def _rebuild_layer(class_name: str) -> Any:
    """Unpickle an LA57 layer (see "Pickling" in the docstring); pickle restores its state."""
    cls = LA57_CLASSES[class_name]
    return object.__new__(cls)


#: The LA57 layer classes by name, for :func:`_rebuild_layer`.
LA57_CLASSES: Dict[str, Type[intel.Intel]] = {cls.__name__: cls for cls in LA57_TWIN.values()}


def _adopt_canonical_name() -> None:
    """One module object and one class path for the LA57 layers (as in ``msl_layer``).

    ``vol -p`` imports this file as :data:`CANONICAL_MODULE`; MemDiver imports it as
    ``memdiver.vol3plugins.memdiver_stackers``. The first copy loaded owns the canonical
    name, a later import under the other name gets that copy back.
    """
    for layer_class in LA57_TWIN.values():
        layer_class.__module__ = CANONICAL_MODULE
    _rebuild_layer.__module__ = MEMDIVER_MODULE
    owner = sys.modules.setdefault(CANONICAL_MODULE, sys.modules[__name__])
    sys.modules[__name__] = owner


_adopt_canonical_name()
