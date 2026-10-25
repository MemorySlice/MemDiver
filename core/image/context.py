"""``ImageContext``: one Volatility 3 context per (image, profile), built once (plan T1.3).

Building a vol3 context over a multi-GB image is the expensive step (format
stacking, a 35-55 MB ISF, the KASLR scan), so it happens once per
``(image sha256, profile sha256)`` and is kept in a small thread-safe LRU
(:class:`ImageContextCache`). Contexts hold open files and vol3 objects: they
are never pickled — a task-manager worker re-creates its own.

Building deliberately does NOT trust vol3's ``LinuxIntelStacker``: on LA57
images it stacks a 4-level layer and every plugin silently returns nothing.
Instead only the *physical* format stackers run (LiME, ELF, AVML, ...), the
KASLR shifts come from vol3's ``find_aslr``, and the paging depth is chosen by
:func:`memdiver.core.image.paging.choose_kernel_layer` (read-back self-test).
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Hashable, Optional

from memdiver.core.constants import memdiver_home
from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory

VOL3_IMAGE_MISSING = missing_package_message("volatility3 (memory-image views)", extra="image")
#: Kernel module name every ImageContext registers its kernel under.
KERNEL_MODULE = "kernel"
#: Symbol table of the registered kernel (addresses masked to the layer's VA width).
KERNEL_TABLE = "kernel_isf"
#: Unmasked table used only while the paging depth is unknown (KASLR + self-test).
PROBE_TABLE = "kernel_isf_probe"


def cache_dir() -> Path:
    """``<memdiver home>/cache/isf`` — ISF files and the image sha256 index."""
    path = memdiver_home() / "cache" / "isf"
    path.mkdir(parents=True, exist_ok=True)
    return path


def file_sha256(path: Path, index_dir: Optional[Path] = None) -> str:
    """sha256 of ``path``, cached by (resolved path, size, mtime_ns)."""
    path = Path(path).resolve()
    stat = path.stat()
    key = f"{path}|{stat.st_size}|{stat.st_mtime_ns}"
    index_file = (index_dir or cache_dir()) / "sha256_index.json"
    index = _load_json(index_file)
    if key not in index:
        index[key] = _hash_file(path)
        index_file.write_text(json.dumps(index, indent=1), encoding="utf-8")
    return index[key]


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(16 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> Dict[str, str]:
    try:
        return dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def require_volatility3() -> None:
    """Raise the one capability error for a missing Volatility 3."""
    try:
        import volatility3.framework  # noqa: F401
    except ImportError as exc:
        raise CapabilityError(VOL3_IMAGE_MISSING, category=ErrorCategory.UNSUPPORTED) from exc


@dataclass
class ImageContext:
    """A vol3 context over one image, optionally with a kernel profile loaded."""

    image_path: Path
    context: Any                        # volatility3 Context
    physical_layer: str
    isf_path: Optional[Path] = None
    kernel_paging: Any = None           # paging.KernelPaging, when a profile is loaded
    #: vol3 contexts are NOT thread-safe, and the cache shares one context across
    #: threads (the web server serves concurrent hex requests). Every vol3 call on
    #: this context — task lookup, process layers, VMA walks, reads — holds this
    #: lock. Unlocked concurrent use was measured to return WRONG answers ("pid not
    #: in task list", a run table one entry short), not just errors.
    lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def __reduce__(self) -> Any:
        raise TypeError("ImageContext holds open vol3 state and is never pickled; "
                        "rebuild it in the worker")

    @property
    def has_kernel(self) -> bool:
        return self.kernel_paging is not None

    @property
    def kernel(self) -> Any:
        """The registered vol3 kernel module."""
        if not self.has_kernel:
            raise CapabilityError("this image view was opened without a kernel profile",
                                  category=ErrorCategory.INVALID_INPUT)
        return self.context.modules[KERNEL_MODULE]

    def canonical_kernel_va(self, address: int) -> int:
        """vol3 object offsets are DE-canonicalized (top bits masked to the VA
        width); every MemDiver kernel_va Location is canonical (``0xff…``/``0xffff…``)."""
        return int(self.context.layers[self.kernel.layer_name].canonicalize(address))

    def describe(self) -> Dict[str, Any]:
        layers = [type(self.context.layers[n]).__name__ for n in _layer_chain(self)]
        return {"physical_layer_chain": layers,
                "kernel": self.kernel_paging.to_dict() if self.has_kernel else None}

    @classmethod
    def build(cls, image_path: Path, isf_path: Optional[Path] = None,
              va_bits_hint: Optional[int] = None,
              dtb: Optional[int] = None) -> "ImageContext":
        """Stack the image's physical layers and, given an ISF, the kernel."""
        require_volatility3()
        ctx = _new_vol3_context()
        physical = _stack_physical(ctx, Path(image_path))
        image_ctx = cls(Path(image_path), ctx, physical, isf_path)
        if isf_path is not None:
            image_ctx.kernel_paging = _load_kernel(ctx, physical, Path(isf_path),
                                                   va_bits_hint, dtb)
        return image_ctx


def _new_vol3_context() -> Any:
    import volatility3.framework.automagic  # noqa: F401  (registers stackers)
    import volatility3.framework.layers
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import contexts
    framework.require_interface_version(2, 0, 0)
    framework.import_files(sys.modules["volatility3.framework.layers"], True)
    framework.import_files(volatility3.plugins, True)  # Linux symbol extensions
    return contexts.Context()


def _stack_physical(ctx: Any, image_path: Path) -> str:
    """FileLayer + every applicable non-OS stacker (LiME, ELF, AVML, QEMU, ...)."""
    from volatility3 import framework
    from volatility3.framework import interfaces
    from volatility3.framework.automagic.stacker import LayerStacker
    from volatility3.framework.layers import physical
    ctx.config["base.location"] = image_path.resolve().as_uri()
    ctx.add_layer(physical.FileLayer(ctx, "base", "base"))
    stackers = [s for s in framework.class_subclasses(interfaces.automagic.StackerLayerInterface)
                if not s.__name__.endswith("IntelStacker")]
    stackers.sort(key=lambda s: getattr(s, "stack_order", 0))
    return LayerStacker.stack_layer(ctx, "base", stack_set=stackers)[0]


def _load_kernel(ctx: Any, physical: str, isf_path: Path,
                 va_bits_hint: Optional[int], dtb: Optional[int]) -> Any:
    from volatility3.framework import contexts
    from volatility3.framework.automagic.linux import LinuxIntelStacker

    from memdiver.core.image.paging import choose_kernel_layer
    _add_symbol_table(ctx, isf_path, PROBE_TABLE)
    kaslr_shift, aslr_shift = LinuxIntelStacker.find_aslr(ctx, PROBE_TABLE, physical)
    # find_aslr registers a throwaway module on the PHYSICAL layer under the same
    # symbol table; vol3's get_module_from_volobj_type would later pick it (e.g.
    # VMA file names then fail in vfsmount._get_real_mnt). Drop it.
    for stray in list(ctx.modules.get_modules_by_symbol_tables(PROBE_TABLE)):
        del ctx.modules[stray]
    paging = choose_kernel_layer(ctx, physical, PROBE_TABLE, kaslr_shift, aslr_shift,
                                 dtb=dtb, va_bits_hint=va_bits_hint)
    # The kernel's table masks symbol addresses to the chosen layer's VA width,
    # as vol3's own LinuxSymbolFinder automagic does. Unmasked (canonical
    # 0xffffffff8...) symbols make vol3 code that canonicalizes symbol + offset
    # overflow 64 bits — linux.psscan failed with struct.error on alma-9.
    # The mask needs the depth, so the probe table above stays unmasked.
    _add_symbol_table(ctx, isf_path, KERNEL_TABLE,
                      symbol_mask=ctx.layers[paging.layer_name].address_mask)
    ctx.symbol_space.remove(PROBE_TABLE)
    contexts.Module.create(ctx, KERNEL_MODULE, paging.layer_name, aslr_shift,
                           symbol_table_name=KERNEL_TABLE)
    return paging


def _add_symbol_table(ctx: Any, isf_path: Path, name: str, symbol_mask: int = 0) -> None:
    from volatility3.framework.symbols.linux import LinuxKernelIntermedSymbols
    config_path = f"temporary.{name}"
    # Into the context config BEFORE construction, like vol3's symbol finder:
    # the table's format delegate copies its config branch at construction, so
    # the constructor's own ``symbol_mask`` argument never reaches it.
    ctx.config[f"{config_path}.symbol_mask"] = symbol_mask
    ctx.symbol_space.append(LinuxKernelIntermedSymbols(
        ctx, config_path, name=name, isf_url=isf_path.resolve().as_uri(),
        symbol_mask=symbol_mask))


def _layer_chain(image_ctx: ImageContext) -> list:
    name: Optional[str] = image_ctx.physical_layer
    chain = []
    while name:
        chain.append(name)
        deps = image_ctx.context.layers[name].dependencies
        name = deps[0] if deps else None
    return chain


class ImageContextCache:
    """Thread-safe LRU of :class:`ImageContext` keyed by (image sha, profile sha, ...)."""

    def __init__(self, maxsize: int = 4) -> None:
        self._maxsize = maxsize
        self._items: "OrderedDict[Hashable, ImageContext]" = OrderedDict()
        self._lock = threading.Lock()

    def get_or_build(self, key: Hashable, build: Callable[[], ImageContext]) -> ImageContext:
        with self._lock:
            if key in self._items:
                self._items.move_to_end(key)
                return self._items[key]
            built = build()   # under the lock: never build the same image twice
            self._items[key] = built
            while len(self._items) > self._maxsize:
                self._items.popitem(last=False)
            return built

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


_CACHE = ImageContextCache()


def get_image_context(image_path: Path, image_sha: str, isf_path: Optional[Path] = None,
                      isf_sha: Optional[str] = None, va_bits_hint: Optional[int] = None,
                      dtb: Optional[int] = None) -> ImageContext:
    """The cached context for this (image, profile, paging override)."""
    # The resolved path is part of the key: a stale or hand-edited sha in a
    # descriptor must never hand back ANOTHER image's context.
    key = (image_sha, str(Path(image_path).resolve()), isf_sha if isf_path else None,
           va_bits_hint, dtb)
    return _CACHE.get_or_build(
        key, lambda: ImageContext.build(image_path, isf_path, va_bits_hint, dtb))


def adapter_for(descriptor: Any, descriptor_path: Path) -> Any:
    """Layer adapter for a ``.mdview`` descriptor (default factory of Vol3LayerSource)."""
    from memdiver.core.image.adapters import adapter_for_view
    isf = descriptor.isf_path(descriptor_path)
    paging = descriptor.paging
    image_ctx = get_image_context(
        descriptor.image_path(descriptor_path), descriptor.image_sha256, isf,
        descriptor.profile.sha256 if descriptor.profile and descriptor.profile.sha256
        else (file_sha256(isf) if isf else None),
        paging.va_bits if paging else None, paging.pgd_phys if paging else None)
    return adapter_for_view(image_ctx, descriptor)
