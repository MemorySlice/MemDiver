"""``linux.btf_layouts`` -- kernel-module struct layouts from the kernel's own BTF in the image.

Lists member offsets/sizes of module structs (``wg_peer``, ``crypt_config`` ...) that no vmlinux
ISF describes, read from the module's resident split BTF (``btf_modules`` walk, cross-checked
against ``btf_vmlinux``) or, as a fallback, found by a BTF-header signature scan of the
physical layer.  The parser and the trust rule live in ``secrets/btf_memory.py``; this file is
the Volatility glue: it takes every ``struct btf`` / ``btf_module`` / ``module`` offset from the
vmlinux ISF (never guessed) and ``recover_module_layouts()`` is the entry point for other
plugins.

``--export`` writes ``btf_offsets.<module>.json`` in the capture-sidecar ``btf_offsets`` shape,
which ``linux.wireguard --offsets`` / ``linux.dmcrypt --offsets`` accept as-is.
"""

import json
import logging
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements

from .kernel_common import isf_offset, isf_size, symbol_address
from .secrets import btf_memory

vollog = logging.getLogger(__name__)

# Structs listed when --struct is not given.
DEFAULT_STRUCTS = {
    "wireguard": ("wg_device", "wg_peer", "noise_handshake", "noise_keypair", "noise_static_identity",
                  "noise_keypairs", "noise_symmetric_key", "cookie_checker", "cookie",
                  "index_hashtable_entry", "allowedips_node"),
    "dm_crypt": ("crypt_config",),
    "dm_mod": ("hash_cell", "mapped_device", "dm_table", "dm_target", "target_type", "dm_dev"),
}
_SYMBOLS = ("btf_modules", "btf_vmlinux", "__start_BTF", "__stop_BTF")
_ARRAY_SIZES = ("btf.name", "module.name")
METHODS = ("auto", "symbols", "scan", "both")


def kernel_btf_layout(vmlinux: Any) -> btf_memory.KernelBtfLayout:
    """``struct btf`` / ``btf_module`` / ``module`` offsets from the vmlinux ISF (missing = absent)."""
    offsets = {key: isf_offset(vmlinux, *key.split(".", 1)) for key in btf_memory.LAYOUT_KEYS + ("btf.name",)}
    sizes = {key: isf_size(vmlinux, key) for key in _ARRAY_SIZES}
    pointer = vmlinux.get_type("pointer")
    data_format = getattr(getattr(pointer, "vol", None), "data_format", None)
    return btf_memory.KernelBtfLayout(
        {k: v for k, v in offsets.items() if v is not None},
        {k: v for k, v in sizes.items() if v},
        pointer.size, getattr(data_format, "byteorder", "little") or "little")


def _symbol_addresses(vmlinux: Any, layer: Any) -> Dict[str, int]:
    """Absolute, canonical symbol addresses (comparable with pointers read from memory)."""
    found = {name: symbol_address(vmlinux, name, layer) for name in _SYMBOLS}
    return {name: address for name, address in found.items() if address is not None}


def _reader(layer: Any, pad: bool):
    def read(address: int, length: int) -> Optional[bytes]:
        try:
            return bytes(layer.read(address, length, pad=pad))
        except (exceptions.InvalidAddressException, ValueError, OverflowError):
            return None
    return read


def _physical_ranges(layer: Any) -> List[Tuple[int, int]]:
    """Mapped ranges of the physical layer under the kernel's virtual layer (merged, sorted)."""
    ranges: List[Tuple[int, int]] = []
    try:
        for offset, length, *_rest in layer.mapping(0, layer.maximum_address, ignore_errors=True):
            if ranges and ranges[-1][0] + ranges[-1][1] == offset:
                ranges[-1] = (ranges[-1][0], ranges[-1][1] + length)
            else:
                ranges.append((offset, length))
    except (exceptions.InvalidAddressException, AttributeError, NotImplementedError, TypeError):
        ranges = [(layer.minimum_address, layer.maximum_address - layer.minimum_address + 1)]
    return ranges


def physical_layer(context: interfaces.context.ContextInterface, virtual_layer: Any) -> Optional[Any]:
    name = virtual_layer.config.get("memory_layer") if hasattr(virtual_layer, "config") else None
    return context.layers[name] if name in context.layers else None


_BASE_CACHE: Dict[str, Any] = {}  # the parsed vmlinux base of the current context (one entry)


def _base_cache(context: Any, kernel_module_name: str) -> Dict[str, Any]:
    """Per-context cache so several modules of one image parse the vmlinux BTF once."""
    if _BASE_CACHE.get("context") is not context or _BASE_CACHE.get("kernel") != kernel_module_name:
        _BASE_CACHE.clear()
        _BASE_CACHE.update(context=context, kernel=kernel_module_name)
    return _BASE_CACHE


def recover_module_layouts(context: interfaces.context.ContextInterface, kernel_module_name: str,
                           module: str, structs: Sequence[str], method: str = "auto"
                           ) -> btf_memory.RecoveredLayouts:
    """Memory-BTF layouts of ``structs`` in kernel module ``module`` (``"vmlinux"`` = base).

    Raises ``btf_memory.BtfParseError`` when nothing usable is found; check ``.trusted`` before
    treating the result like a built-in table entry.
    """
    vmlinux = context.modules[kernel_module_name]
    virtual = context.layers[vmlinux.layer_name]
    physical = physical_layer(context, virtual) if method in ("auto", "scan", "both") else None
    return btf_memory.recover_layouts(
        _reader(virtual, pad=False), kernel_btf_layout(vmlinux), _symbol_addresses(vmlinux, virtual),
        module, list(structs),
        scan_read=_reader(physical, pad=True) if physical is not None else None,
        scan_ranges=_physical_ranges(physical) if physical is not None else None,
        method=method, base_cache=_base_cache(context, kernel_module_name))


# Consumer plugins (linux.wireguard / linux.dmcrypt) can only USE a walk result (a scan result is
# never trusted), so they offer no "scan": auto/symbols = walk only, both = walk + scan cross-check.
BTF_METHOD_CHOICES = ("auto", "symbols", "both", "off")
_CONSUMER_METHODS = {"auto": "symbols", "symbols": "symbols", "both": "both"}


def btf_method_requirement() -> requirements.ChoiceRequirement:
    """The ``--btf-method`` option shared by the plugins that read module offsets."""
    return requirements.ChoiceRequirement(
        name="btf_method", choices=list(BTF_METHOD_CHOICES), optional=True, default="auto",
        description="Module struct offsets from the kernel's in-memory BTF (btf_modules walk): "
                    "auto/symbols = walk only, both = walk + physical BTF-header scan that must "
                    "agree, off = built-in table / --offsets only")


def recover_trusted(context: Any, kernel_module_name: str, module: str, structs: Sequence[str],
                    method: Optional[str]) -> Optional[btf_memory.RecoveredLayouts]:
    """A TRUSTED memory-BTF recovery, or None (method ``off``, nothing found, partial, ambiguous).

    Every reason for None is logged at INFO: the caller then keeps its table/derived path.
    """
    method = _CONSUMER_METHODS.get(method or "auto")
    if method is None or context is None:  # "off" (or an unknown value): never read memory
        return None
    try:
        recovered = recover_module_layouts(context, kernel_module_name, module, structs, method)
    except btf_memory.BtfParseError as error:
        vollog.info("btf-memory %s: not used (%s)", module, error)
        return None
    except (exceptions.VolatilityException, KeyError, AttributeError, ValueError, TypeError,
            MemoryError) as error:
        vollog.info("btf-memory %s: not used (%s: %s)", module, type(error).__name__, error)
        return None
    for note in recovered.notes:
        vollog.info("btf-memory %s: %s", module, note)
    if not recovered.trusted:
        vollog.info("btf-memory %s: not trusted (method %s, missing %s, %d scan blobs): not used",
                    module, recovered.method, ", ".join(recovered.missing) or "none", recovered.scan_blobs)
        return None
    return recovered


class BtfLayouts(interfaces.plugins.PluginInterface):
    """Lists kernel-module struct layouts recovered from the kernel's in-memory BTF."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.StringRequirement(
                name="module", optional=True, default="wireguard",
                description="Kernel module whose BTF to read (vmlinux = the base BTF)"),
            requirements.ListRequirement(
                name="struct", element_type=str, optional=True,
                description="Struct names (default: the plugin set for wireguard/dm_crypt/dm_mod)"),
            requirements.ChoiceRequirement(
                name="method", choices=list(METHODS), optional=True, default="auto",
                description="symbols = btf_modules walk; scan = BTF header scan; auto = walk, else scan; "
                            "both = both, must agree"),
            requirements.BooleanRequirement(
                name="export", optional=True, default=False,
                description="Write btf_offsets.<module>.json (accepted by --offsets of linux.wireguard/dmcrypt)"),
        ]

    def _structs(self, module: str) -> List[str]:
        return list(self.config.get("struct") or DEFAULT_STRUCTS.get(module, ()))

    def _generator(self, recovered: btf_memory.RecoveredLayouts) -> Iterator[Tuple[int, Tuple]]:
        label = "%s%s" % (recovered.method, "" if recovered.trusted else " (untrusted)")
        for layout in recovered.structs.values():
            yield 0, (recovered.module, layout.name, "(sizeof)", layout.size, layout.size, 0, 0,
                      "%s %s" % (layout.kind, layout.name), label)
            for member in layout.members:
                yield 1, (recovered.module, layout.name, member.name, member.offset,
                          -1 if member.size is None else member.size, member.bit_offset,
                          member.bitfield_size, member.type_name, label)

    def run(self) -> renderers.TreeGrid:
        columns = [("Module", str), ("Struct", str), ("Member", str), ("Offset", int), ("Size", int),
                   ("BitOffset", int), ("BitSize", int), ("Type", str), ("Method", str)]
        module = self.config.get("module") or "wireguard"
        structs = self._structs(module)
        if not structs:
            vollog.error("btf: no default structs for %s; pass --struct", module)
            return renderers.TreeGrid(columns, iter(()))
        try:
            recovered = recover_module_layouts(self.context, self.config["kernel"], module, structs,
                                               self.config.get("method") or "auto")
        except btf_memory.BtfParseError as error:
            vollog.error("btf: %s", error)
            return renderers.TreeGrid(columns, iter(()))
        for note in recovered.notes:
            vollog.info("btf: %s", note)
        vollog.info("btf: %s", recovered.source)
        if recovered.missing:
            vollog.warning("btf: %s has no %s", module, ", ".join(recovered.missing))
        if self.config.get("export"):
            with self.open("btf_offsets.%s.json" % module) as handle:
                handle.write(json.dumps({"btf_offsets": recovered.document()}, indent=1).encode())
        return renderers.TreeGrid(columns, self._generator(recovered))
